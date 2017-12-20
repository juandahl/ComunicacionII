/* Copyright (C) 2013-2017  B.A.T.M.A.N. contributors:
 *
 * Antonio Quartulli
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "bat_v_ogm.h"
#include "main.h"

#include <linux/atomic.h>
#include <linux/byteorder/generic.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/fs.h>
#include <linux/if_ether.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "bat_algo.h"
#include "hard-interface.h"
#include "hash.h"
#include "log.h"
#include "originator.h"
#include "packet.h"
#include "routing.h"
#include "send.h"
#include "translation-table.h"
#include "tvlv.h"

/**
 * batadv_v_ogm_orig_get - retrieve and possibly create an originator node
 * @bat_priv: the bat priv with all the soft interface information
 * @addr: the address of the originator
 *
 * Return: the orig_node corresponding to the specified address. If such object
 * does not exist it is allocated here. In case of allocation failure returns
 * NULL.
 */
//En cada interfaz batman de un nodo, se almacena informacion de varios tipos.
//Entre esa informacion se almacenan los demas nodos de la red mesh, llamados originators.
//Por cada originator tenemos una struct batadv_orig_node que contiene esa informaciom
//Los punteros a esas structs se almacenan a su vez en una tabla de hashing para accederlas mas rapidamente.
//Ese acceso se realiza en base a la MAC del nodo originator.
//
//Esta funcion (batadv_v_ogm_orig_get) recibe una MAC, y se encarga de buscar un originator con esa mac; en caso 
//de encontrarlo devuelve un puntero a su struct, y en caso de no encontrarlo trata de agregar un nuevo elemento 
//(struct batadv_orig_node) a la tabla de hash.
//Si puede hacerlo, devuelve el puntero, y si no puede, devuelve NULL

//Es invocada en
//bat_v_elp.c: batadv_v_elp_neigh_update
//  Esta funcion es invocada cuando se recibe un paquete elp por una interfaz, para actualizar
//  la info del nodo vecino que lo envio.
//  Invoca a batadv_v_ogm_orig_get con el nodo que envio el elp (elp_packet->orig, que es la mac
//  del nodo emisor) para que devuelva un puntero a los datos de ese nodo (struct batadv_orig_node *) 
//  o lo cree si no existe
//bat_v_ogm.c: batadv_v_ogm_process
//  Cuando se recibe un paquete tipo OGM, en el puede haber varios ogms que se van agregando al paquete
//  a medida que recorre los nodos mesh.
//  Al recibirlo, se invoca a batadv_v_ogm_process pasandole entre otras cosas el sk buffer y el offset
//  en el, para poder ubicar el ogm que se esta procesando. 
//  En esta funcion se hacen validaciones acerca del throughput y del neighbor del cual se recibio el ogm, 
//  y si esto es correcto, se invoca a batadv_v_ogm_orig_get para obtener el puntero a la struct
//  batadv_orig_node del nodo que origino este ogm, o bien crearla si no existe.
//bat_v_ogm.c: batadv_v_ogm_route_update
//  batadv_v_ogm_route_update actualiza las rutas en base a un ogm recibido.
//  Invoca a batadv_v_ogm_orig_get para obtener o crear la struct batadv_orig_node correspondiente al nodo
//  neigbor que envio (no necesariamente origino) el ogm. La mac la recibe como parametro, y es la mac origen 
//  del frame ethernet que encapsula al ogm
//
//Las secuencias de llamado a batadv_v_ogm_orig_get son las siguientes (esto solo va si no son demasiadas)
//batadv_v_ogm_process----->batadv_v_ogm_orig_get
//batadv_v_ogm_process----->batadv_v_ogm_process_per_outif----->batadv_v_ogm_route_update----->batadv_v_ogm_orig_get
//
//batadv_v_ogm_orig_get se publica en bat_v_ogm.h
struct batadv_orig_node *batadv_v_ogm_orig_get(struct batadv_priv *bat_priv,
					       const u8 *addr)
{
	struct batadv_orig_node *orig_node;
	int hash_added;

	//return orig_node if it exists in the has table. Otherwise NULL
//Busca en la hash table de originators que conoce el nodo, uno que tenga la direccion ethernet pasada 
//como parametro, en este caso addr, que es la mac del originator, Si el originator ya esta en la tabla, 
//devuelve un puntero a su struct correspondiente; 
	orig_node = batadv_orig_hash_find(bat_priv, addr);
	if (orig_node)
		return orig_node;

//Si el originator no fue encontardo, trata de crear una struct para el, 
	orig_node = batadv_orig_node_new(bat_priv, addr);
	if (!orig_node)
		return NULL;
//Si llega aca, pudo crear la struct para el originator....
	 // kref_get - increment refcount for object.
//estoy usando la struct, incremento el contador (kref) para que no la borren (esto no es necesario comentarlo porque
//es una funcion del kernel)
	kref_get(&orig_node->refcount);
//aca trata de agregar la entrada en la hash table... retorna null y libera memoria si no puede
//retorna el puntero a la struct si pudo crear 
	hash_added = batadv_hash_add(bat_priv->orig_hash, batadv_compare_orig,
				     batadv_choose_orig, orig_node,
				     &orig_node->hash_entry);
	//si hubo error al agregar a la tabla
	if (hash_added != 0) {
		/* remove refcnt for newly created orig_node and hash entry */
//decrementa reference counts (y posiblemente libere memoria), tambien del kernel
		batadv_orig_node_put(orig_node);
		batadv_orig_node_put(orig_node);
		orig_node = NULL;
	}

	return orig_node;
}

/**
 * batadv_v_ogm_start_timer - restart the OGM sending timer
 * @bat_priv: the bat priv with all the soft interface information
 */
//La tarea de esta funcion es reiniciar el timer de envio de paquetes OGM
//para ello necesita la informacion de la interfaz pero principalmente la cola 
//de trabajo de la interfaz
// Esta funcion puede ser invocada para replanificar un envio de ogm o 
// para activar una interfaz(por eso es que es llamada por batadv_v_ogm_send o
// batadv_v_ogm_iface_enable)

//Es invocada en
//bat_v_ogm.c: batadv_v_ogm_send
//Si no se puede enviar el paquete y hay que replanificar se llama a batadv_v_ogm_start_timer
//para reiniciar el timer de envio de paquetes OGM 
//bat_v_ogm.c: batadv_v_ogm_iface_enable
//A partir de una interfaz pasada por parametro se prepara o inicializa valores
//para su posterior uso
//Luego de obtener la informacion de la interfaz, se actualiza el timer de envio
//OGM de la interfaz con valores iniciales usando la funcion batadv_v_ogm_start_timer


//Las secuencias de llamado a batadv_v_ogm_start_timer son las siguientes 
//batadv_v_ogm_send----->batadv_v_ogm_start_timer
//batadv_v_ogm_iface_enable----->batadv_v_ogm_start_timer
static void batadv_v_ogm_start_timer(struct batadv_priv *bat_priv)
{
	unsigned long msecs;
	/* this function may be invoked in different contexts (ogm rescheduling
	 * or hard_iface activation), but the work timer should not be reset
	 */
	 //Determina si hay paquetes OGM pendientes en la cola de trabajo 
	if (delayed_work_pending(&bat_priv->bat_v.ogm_wq))
		return;
    //si no hay trabajo pendiente se llega aca
	//Kernel functions para calcular intervalos de tiempo
	msecs = atomic_read(&bat_priv->orig_interval) - BATADV_JITTER;
	msecs += prandom_u32() % (2 * BATADV_JITTER);
	//queue_delayed_work - queue work on a workqueue after delay
	queue_delayed_work(batadv_event_workqueue, &bat_priv->bat_v.ogm_wq,
			   msecs_to_jiffies(msecs));
}

/**
 * batadv_v_ogm_send_to_if - send a batman ogm using a given interface
 * @skb: the OGM to send
 * @hard_iface: the interface to use to send the OGM
 */

// Recibe como parametro el paquete OGM a enviar y la interfaz por la que será enviado 
//El metodo verifica que la interfaz no este activa(si es asi aborta)
//Si no tiene que abortar el envio, lo realiza mediante el llamado a
//batadv_send_broadcast_skb. Este metodo envia un paquete por una inetrfaz especificada
//por parametro

//Es invocada en
//bat_v_ogm.c: batadv_v_ogm_send
//Verifica que el estado de la mesh no este desactivado.
//Se obtiene el OGM del buffer y se verifica si el paquete necesita (re)broadcast 
// Se utiliza concurrencia para enviar a todas las interfaces. Aca es donde se usa
// batadv_v_ogm_send_to_if para enviar el paquete a una interfaz determinada

//bat_v_ogm.c: batadv_v_ogm_forward
//El primer chequeo que se realiza es que no se reenvie por default
//Chequea que no se envie dos veces el mismo paquete usando el numero de secuencia
//Se controla que el paquete no tenga que ser descartado por el time to live agotado
//Si no sucede lo anterior se reduce el ttl en 1, se agrega penalidad por reenvio 
//y se reenvia por la interfaz saliente pasada por parametro usando el metodo  
//batadv_v_ogm_send_to_if

//Las secuencias de llamado a batadv_v_ogm_iface_enable son las siguientes 
//batadv_v_ogm_send----->batadv_v_ogm_send_to_if
//batadv_v_ogm_forward----->batadv_v_ogm_send_to_if
static void batadv_v_ogm_send_to_if(struct sk_buff *skb,
				    struct batadv_hard_iface *hard_iface)
{

 	//Obtiene la informacion privada del dispositivo de red
	struct batadv_priv *bat_priv = netdev_priv(hard_iface->soft_iface);

	//Si la interfaz esta ocupada(activa) termina la ejecucion
	if (hard_iface->if_status != BATADV_IF_ACTIVE)
		return;

    //si llega aca es porque la interfaz se puede usar
	/* Stop preemption on local cpu while incrementing the counter */
	batadv_inc_counter(bat_priv, BATADV_CNT_MGMT_TX);
	/* Stop preemption on local cpu while incrementing the counter */
	batadv_add_counter(bat_priv, BATADV_CNT_MGMT_TX_BYTES,
			   skb->len + ETH_HLEN);

	//Send out an already prepared packet to the given neighbor or broadcast it using the specified interface
	batadv_send_broadcast_skb(skb, hard_iface);
}

/**
 * batadv_v_ogm_send - periodic worker broadcasting the own OGM
 * @work: work queue item
 */
//Verifica que el estado de la mesh no este desactivado.
//Se obtiene el OGM del buffer y se verifica si el paquete necesita (re)broadcast 
// Se utiliza concurrencia para enviar a todas las interfaces

//Es invocada en
//bat_v.c: batadv_v_ogm_init
// batadv_v_ogm_init se encarga de inicializar el buffer OGM y la workqueue preparando
// un paquete OGM inicial. Setea valores para preparar la cola de trabajo y es luego de esto
//donde envia un paquete OGM llamando al metodo batadv_v_ogm_send

//Las secuencias de llamado a batadv_v_ogm_iface_enable son las siguientes 
//batadv_v_ogm_init----->batadv_v_ogm_iface_enable

static void batadv_v_ogm_send(struct work_struct *work)
{
    //Crea struct hard_iface. Dispositivo de red conocido por BATMAN-adv
	struct batadv_hard_iface *hard_iface;
	//Crea struct de datos de la interfaz privada
	struct batadv_priv_bat_v *bat_v;
	//Crea struct de la informacion de la interfaz mesh
	struct batadv_priv *bat_priv;
	//Crea struct de paquete OGM
	struct batadv_ogm2_packet *ogm_packet;
	//crea dos struct de buffers
	struct sk_buff *skb, *skb_tmp;
	unsigned char *ogm_buff, *pkt_buff;
	int ogm_buff_len;
	u16 tvlv_len = 0;
	int ret;

    //Macro de kernel.
	bat_v = container_of(work, struct batadv_priv_bat_v, ogm_wq.work);
	bat_priv = container_of(bat_v, struct batadv_priv, bat_v);

	//Chequea que el estado de la mesh no sea "BATADV_MESH_DEACTIVATING". De ser
	//asi se redirige al bloque out
	if (atomic_read(&bat_priv->mesh_state) == BATADV_MESH_DEACTIVATING)
		goto out;

	ogm_buff = bat_priv->bat_v.ogm_buff;
	ogm_buff_len = bat_priv->bat_v.ogm_buff_len;
	
	/* tt changes have to be committed before the tvlv data is
	 * appended as it may alter the tt tvlv container
	 */
	//confirmar todos los cambios tt locales pendientes que se han puesto
	//en cola en el tiempo transcurrido desde la última confirmación 
	batadv_tt_local_commit_changes(bat_priv);
	//Agrega el contenido del contenedor tvlv a un buffer de paquetes OGM dado
	tvlv_len = batadv_tvlv_container_ogm_append(bat_priv, &ogm_buff,
						    &ogm_buff_len,
						    BATADV_OGM2_HLEN);

	bat_priv->bat_v.ogm_buff = ogm_buff;
	bat_priv->bat_v.ogm_buff_len = ogm_buff_len;

	skb = netdev_alloc_skb_ip_align(NULL, ETH_HLEN + ogm_buff_len);
	//si es null se redirge al bloque reschedule
	if (!skb)
		goto reschedule;

		//Incrementa el espacio libre de un &sk_buff vacio reduciendo el espacio
	//de la cola. Solo es permitido para un buffer vacio
	skb_reserve(skb, ETH_HLEN);
	
	//Agrega informacion al buffer. Si excede el total del tamaño del buffer
	//el kernel entra en problemas. Un puntero al primer byte de la informacion extra
	//es devuelto 
	pkt_buff = skb_put(skb, ogm_buff_len);
	//copia un bloque de memoria
	//destination: skb_buff
	//source: ogm_received
	//size_t: packet_len
	memcpy(pkt_buff, ogm_buff, ogm_buff_len);

	//Guarda en una variable un paquete OGM del buffer
	ogm_packet = (struct batadv_ogm2_packet *)skb->data;
	//Guarda en una variable eñ numero de secuencia 
	//existe una conversion explicita de tipos
	ogm_packet->seqno = htonl(atomic_read(&bat_priv->bat_v.ogm_seqno));
	//incrementa el numero de secuencia
	atomic_inc(&bat_priv->bat_v.ogm_seqno);
    //Asignacion de tvlv_leng al paqiete. Hay conversion(htons)
	ogm_packet->tvlv_len = htons(tvlv_len);

	/* broadcast on every interface */
	//Sentencia para manejar concurrencia
	rcu_read_lock();

	/**
	   MACRO
	 * list_for_each_entry_rcu	-	iterate over rcu list of given type
	 *
	 * This list-traversal primitive may safely run concurrently with
	 * the _rcu list-mutation primitives such as list_add_rcu()
	 * as long as the traversal is guarded by rcu_read_lock().
	 */
	//Macro para iterar sobre la lista rcu. Se ejecuta concurrentemente
	list_for_each_entry_rcu(hard_iface, &batadv_hardif_list, list) {
		if (hard_iface->soft_iface != bat_priv->soft_iface)
			continue;

		/**
		 * kref_get_unless_zero - Increment refcount for object unless it is zero.
		 * @kref: object.
		 *
		 * Return non-zero if the increment succeeded. Otherwise return 0.
		 */
		//Incrementa refcount al objeto a menos que sea cero-
		if (!kref_get_unless_zero(&hard_iface->refcount))
			//Fuerza a que comience una nueva vuelta dentro del ciclo
			continue;

		 
		//Verifica si el paquete necesita (re)broadcast sobre la interfaz entregada
		//Retorna los siguientes posibles valores:
		//	BATADV_HARDIF_BCAST_NORECIPIENT: No neighbor on interface
	    //	BATADV_HARDIF_BCAST_DUPFWD: Just one neighbor, but it is the forwarder
		//	BATADV_HARDIF_BCAST_DUPORIG: Just one neighbor, but it is the originator
		//	BATADV_HARDIF_BCAST_OK: Several neighbors, must broadcast
		 
		ret = batadv_hardif_no_broadcast(hard_iface, NULL, NULL);
		//Analiza la salida de batadv_hardif_no_broadcast almacenada en ret y
		//actualiza el type
		if (ret) {
			char *type;

			switch (ret) {
			case BATADV_HARDIF_BCAST_NORECIPIENT:
				type = "no neighbor";
				break;
			case BATADV_HARDIF_BCAST_DUPFWD:
				type = "single neighbor is source";
				break;
			case BATADV_HARDIF_BCAST_DUPORIG:
				type = "single neighbor is originator";
				break;
			default:
				type = "unknown";
			}
			//Agrega log 
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv, "OGM2 from ourselve on %s surpressed: %s\n",
				   hard_iface->net_dev->name, type);


			//reduce el refcounter de hard_iface y posiblemente lo libera
			batadv_hardif_put(hard_iface);
			continue;
		}

		//Agrega log de envio de paquete OGM con su informacion
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Sending own OGM2 packet (originator %pM, seqno %u, throughput %u, TTL %d) on interface %s [%pM]\n",
			   ogm_packet->orig, ntohl(ogm_packet->seqno),
			   ntohl(ogm_packet->throughput), ogm_packet->ttl,
			   hard_iface->net_dev->name,
			   hard_iface->net_dev->dev_addr);

		/* this skb gets consumed by batadv_v_ogm_send_to_if() */
		//se duplica el buffer. El nuevo buffer tiene su refcount en 1
		skb_tmp = skb_clone(skb, GFP_ATOMIC);
		//Chequea que no haya fallado la clonacion(distinto de null)
		if (!skb_tmp) {

			//si falla decrementa el refcounter de hard_iface y posiblemente lo libera 
			batadv_hardif_put(hard_iface);
			break;
		}

		//Envia un paquete OGM batman(skb_temp) usando la interfaz pasada por paramentro(hard_iface)
		batadv_v_ogm_send_to_if(skb_tmp, hard_iface);

		//decrementa el refcounter de hard_iface y posiblemente lo libera 
		batadv_hardif_put(hard_iface);
	}
	//rcu_read_unlock() - marks the end of an RCU read-side critical section.
	//termina la concurrencia
	rcu_read_unlock();

	/**
	 *	Drop a ref to the buffer and free it if the usage count has hit zero
	 *	Functions identically to kfree_skb, but kfree_skb assumes that the frame
	 *	is being dropped after a failure and notes that
	 */
	consume_skb(skb);

reschedule:
	/**
	 * batadv_v_ogm_start_timer - restart the OGM sending timer
	 * @bat_priv: the bat priv with all the soft interface information
	 */
	//reinicia el timer de envio de pauetes OGM de la itnerfaz
	batadv_v_ogm_start_timer(bat_priv);
out:
	return;
}

/**
 * batadv_v_ogm_iface_enable - prepare an interface for B.A.T.M.A.N. V
 * @hard_iface: the interface to prepare
 *
 * Takes care of scheduling own OGM sending routine for this interface.
 *
 * Return: 0 on success or a negative error code otherwise
 */

//A partir de una interfaz pasada por parametro se prepara o inicializa valores
//para su posterior uso
//Luego de obtener la informacion de la interfaz, se actualiza el timer de envio
//OGM de la interfaz con valores iniciales usando la funcion batadv_v_ogm_start_timer
//se retorna 0 o el numero de error(negativo) en otro caso

//Es invocada en
//bat_v.c: batadv_v_iface_enable
// Este metodo habilita tanto la interfaz para el envio de paquetes OGM como asi tambien
//para paquetes ELP.

//Las secuencias de llamado a batadv_v_ogm_iface_enable son las siguientes 
//batadv_v_iface_enable----->batadv_v_ogm_iface_enable

//batadv_v_ogm_iface_enable se publica en bat_v_ogm.h
int batadv_v_ogm_iface_enable(struct batadv_hard_iface *hard_iface)
{

	//Obtiene la informacion privada del dispositivo de red
	struct batadv_priv *bat_priv = netdev_priv(hard_iface->soft_iface);

	/**
	 * batadv_v_ogm_start_timer - restart the OGM sending timer
	 * @bat_priv: the bat priv with all the soft interface information
	 */
	//reinicia el timer de envio OGM 
	batadv_v_ogm_start_timer(bat_priv);

	return 0;
}

/**
 * batadv_v_ogm_primary_iface_set - set a new primary interface
 * @primary_iface: the new primary interface
 */
//Setea una interfaz primaria. Antes chequea que haya paquetes en el buffer sino 
//termina la ejecucion de la funcion.
//si hay paquetes copia la direccion ethernet de la interfaz al paquete 

//Es invocada en
//bat_v.c: batadv_v_ogm_metric_update
//batadv_v_primary_iface_set setea una interfaz primeria para paquetes ogm y elp.
//para los primeros llama a batadv_v_ogm_primary_iface_set pasandole la interfaz
//por parametro

//Las secuencias de llamado a batadv_v_ogm_primary_iface_set son las siguientes 
//batadv_v_primary_iface_set----->batadv_v_ogm_primary_iface_set

//batadv_v_ogm_primary_iface_set se publica en bat_v_ogm.h
void batadv_v_ogm_primary_iface_set(struct batadv_hard_iface *primary_iface)
{

	//Obtiene la informacion privada del dispositivo de red
	struct batadv_priv *bat_priv = netdev_priv(primary_iface->soft_iface);
	//crea struct de paquete OGM
	struct batadv_ogm2_packet *ogm_packet;

	//si no hay paquetes termina la ejecucion de la funcion
	if (!bat_priv->bat_v.ogm_buff)
		return;

	//se obtiene el paquete OGM del buffer
	ogm_packet = (struct batadv_ogm2_packet *)bat_priv->bat_v.ogm_buff;
	
	//Copia la direccion ethernet de primary_iface->net_dev->dev_addr a
	//ogm_packet->orig 
	ether_addr_copy(ogm_packet->orig, primary_iface->net_dev->dev_addr);
}

/**
 * batadv_v_forward_penalty - apply a penalty to the throughput metric forwarded
 *  with B.A.T.M.A.N. V OGMs
 * @bat_priv: the bat priv with all the soft interface information
 * @if_incoming: the interface where the OGM has been received
 * @if_outgoing: the interface where the OGM has to be forwarded to
 * @throughput: the current throughput
 *
 * Apply a penalty on the current throughput metric value based on the
 * characteristic of the interface where the OGM has been received. The return
 * value is computed as follows:
 * - throughput * 50%          if the incoming and outgoing interface are the
 *                             same WiFi interface and the throughput is above
 *                             1MBit/s
 * - throughput                if the outgoing interface is the default
 *                             interface (i.e. this OGM is processed for the
 *                             internal table and not forwarded)
 * - throughput * hop penalty  otherwise
 *
 * Return: the penalised throughput metric.
 */

//Recibiendo por parametro la interfaz entrante y saliente y el rendimiento
//actualiza este valor de acuerdo a las caracteristicas descriptas en la cabecera
//de la funcion

//Es invocada en
//bat_v_ogm.c: batadv_v_ogm_metric_update
//batadv_v_ogm_metric_update verifica que el paquete recibido por parametro no haya sido ya actualizado
//comparando los seqno.
//Actualiza los valores de seqno y ultima vez de las interfaces
//Luego actualiza los nuevos valores de metricas de acuerdo a diferentes condiciones
//llamando al metodo batadv_v_forward_penalty 

//Las secuencias de llamado a batadv_v_ogm_metric_update son las siguientes 
//batadv_v_ogm_metric_update----->batadv_v_forward_penalty
static u32 batadv_v_forward_penalty(struct batadv_priv *bat_priv,
				    struct batadv_hard_iface *if_incoming,
				    struct batadv_hard_iface *if_outgoing,
				    u32 throughput)
{
	//inicializacion de variables
	int hop_penalty = atomic_read(&bat_priv->hop_penalty);
	int hop_penalty_max = BATADV_TQ_MAX_VALUE;

	/* Don't apply hop penalty in default originator table. */
	if (if_outgoing == BATADV_IF_DEFAULT)
		return throughput;

	/* Forwarding on the same WiFi interface cuts the throughput in half
	 * due to the store & forward characteristics of WIFI.
	 * Very low throughput values are the exception.
	 */
	if ((throughput > 10) &&
	    (if_incoming == if_outgoing) &&
	    !(if_incoming->bat_v.flags & BATADV_FULL_DUPLEX))
		return throughput / 2;

	/* hop penalty of 255 equals 100% */
	return throughput * (hop_penalty_max - hop_penalty) / hop_penalty_max;
}

/**
 * batadv_v_ogm_forward - check conditions and forward an OGM to the given
 *  outgoing interface
 * @bat_priv: the bat priv with all the soft interface information
 * @ogm_received: previously received OGM to be forwarded
 * @orig_node: the originator which has been updated
 * @neigh_node: the neigh_node through with the OGM has been received
 * @if_incoming: the interface on which this OGM was received on
 * @if_outgoing: the interface to which the OGM has to be forwarded to
 *
 * Forward an OGM to an interface after having altered the throughput metric and
 * the TTL value contained in it. The original OGM isn't modified.
 */

//El primer chequeo que se realiza es que no se reenvie por default
//Chequea que no se envie dos veces el mismo paquete usando el numero de secuencia
//Se controla que el paquete no tenga que ser descartado por el time to live agotado
//Si no sucede lo anterior se reduce el ttl en 1, se agrega penalidad por reenvio 
//y se reenvia por la interfaz saliente pasada por parametro 

//Es invocada en
//bat_v_ogm.c: batadv_v_ogm_process_per_outif
//batadv_v_ogm_process_per_outif recibe como parametro la informacion de la interfaz, el header ethernet, 
// OGM2, el nodo Originator y el vecino, las interfaces salientes y entrantes
//batadv_v_ogm_process_per_outif actualiza las metricas de rendimiento y reenvia el paquete. Para actualizar
//las rutas y saber si debe ser reenviado el paquete se llama al metodo batadv_v_ogm_route_update. El reenvio
//del paquete se hace efectivo llamando a este metodo batadv_v_ogm_forward

//Las secuencias de llamado a batadv_v_ogm_forward son las siguientes 
//batadv_v_ogm_process_per_outif----->batadv_v_ogm_forward

static void batadv_v_ogm_forward(struct batadv_priv *bat_priv,
				 const struct batadv_ogm2_packet *ogm_received,
				 struct batadv_orig_node *orig_node,
				 struct batadv_neigh_node *neigh_node,
				 struct batadv_hard_iface *if_incoming,
				 struct batadv_hard_iface *if_outgoing)
{
	//declaracion de struct con la información vecina por interfaz saliente
	struct batadv_neigh_ifinfo *neigh_ifinfo = NULL;
	//declaracion de struct con la información del originador por interfaz saliente
	struct batadv_orig_ifinfo *orig_ifinfo = NULL;
	//estructura para vecinos de saltos individuales
	struct batadv_neigh_node *router = NULL;
	//paquete OGM a ser reenviado
	struct batadv_ogm2_packet *ogm_forward;
	unsigned char *skb_buff;
	//socket buffer
	struct sk_buff *skb;
	size_t packet_len;
	u16 tvlv_len;

	/* only forward for specific interfaces, not for the default one. */
	//si es por default se redirige a out
	if (if_outgoing == BATADV_IF_DEFAULT)
		goto out;


	//busca y posiblemente crea un objeto orig_ifinfo a partir del nodo origen a ser consultado
	//y la interfaz por la que deberia ser enviado
	//retorna null si falla o el objeto orig_ifinfo para la interfaz saliente. El objeto es creado
	//y agregado a la lista si no existe
	//el objeto se retorna con el refcounter aumentado en 1
	orig_ifinfo = batadv_orig_ifinfo_new(orig_node, if_outgoing);
	//verifica que no hubo fallas en la asignacion anterior. Si hubo se redirige al bloque out
	if (!orig_ifinfo)
		goto out;

	/* acquire possibly updated router */
	//rutea al creador dependiendo de iface
	router = batadv_orig_router_get(orig_node, if_outgoing);

	/* strict rule: forward packets coming from the best next hop only */
	if (neigh_node != router)
		goto out;

	/* don't forward the same seqno twice on one interface */
	if (orig_ifinfo->last_seqno_forwarded == ntohl(ogm_received->seqno))
		goto out;

	//actualiza el valor de numero de secuencia reenviado
	orig_ifinfo->last_seqno_forwarded = ntohl(ogm_received->seqno);

	//se agrega log si el ttl es excedido
	if (ogm_received->ttl <= 1) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv, "ttl exceeded\n");
		goto out;
	}


	//encuentra la interfaz a partir de una nodo vecino
	//el objeto se devuelve con el refcounter incrementado en 1
	//retorna null si no lo encontro
	neigh_ifinfo = batadv_neigh_ifinfo_get(neigh_node, if_outgoing);
	//si no se encontro se redirige al bloque out
	if (!neigh_ifinfo)
		goto out;

	//converts unsigned short integer netshort from network byte order to host byte 
	tvlv_len = ntohs(ogm_received->tvlv_len);

	//actualizacion del tamaño del paquete
	packet_len = BATADV_OGM2_HLEN + tvlv_len;
	skb = netdev_alloc_skb_ip_align(if_outgoing->net_dev,
					ETH_HLEN + packet_len);
	if (!skb)
		goto out;


	//Incrementa el espacio libre de un &sk_buff vacio reduciendo el espacio
	//de la cola. Solo es permitido para un buffer vacio
	skb_reserve(skb, ETH_HLEN);
 
	//Agrega informacion al buffer. Si excede el total del tamaño del buffer
	//el kernel entra en problemas. Un puntero al primer byte de la informacion extra
	//es devuelto 
	skb_buff = skb_put(skb, packet_len);
	//copia un bloque de memoria
	//destination: skb_buff
	//source: ogm_received
	//size_t: packet_len
	memcpy(skb_buff, ogm_received, packet_len);

	/* apply forward penalty */
	ogm_forward = (struct batadv_ogm2_packet *)skb_buff;
	//conversion de tipos
	ogm_forward->throughput = htonl(neigh_ifinfo->bat_v.throughput);
	//reduccion de ttl
	ogm_forward->ttl--;

	//add log de reenvio de paquete OGM
	batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
		   "Forwarding OGM2 packet on %s: throughput %u, ttl %u, received via %s\n",
		   if_outgoing->net_dev->name, ntohl(ogm_forward->throughput),
		   ogm_forward->ttl, if_incoming->net_dev->name);


	//envio un paquete ogm usando la interfaz pasada por parametro
	batadv_v_ogm_send_to_if(skb, if_outgoing);

out:
	//verifica por que condicion entra al bloque
	if (orig_ifinfo)
		//decrementa el refcounter de org_ifinfo y posiblemente lo libera
		batadv_orig_ifinfo_put(orig_ifinfo);
	if (router)
		//decrementa el refcounter de router y posiblemente lo libera
		batadv_neigh_node_put(router);
	if (neigh_ifinfo)
		//decrementa el refcounter de neigh_ifinfo y posiblemente lo libera
		batadv_neigh_ifinfo_put(neigh_ifinfo);
}

/**
 * batadv_v_ogm_metric_update - update route metric based on OGM
 * @bat_priv: the bat priv with all the soft interface information
 * @ogm2: OGM2 structure
 * @orig_node: Originator structure for which the OGM has been received
 * @neigh_node: the neigh_node through with the OGM has been received
 * @if_incoming: the interface where this packet was received
 * @if_outgoing: the interface for which the packet should be considered
 *
 * Return:
 *  1  if the OGM is new,
 *  0  if it is not new but valid,
 *  <0 on error (e.g. old OGM)
 */
//Verifica que el paquete recibido por parametro no haya sido ya actualizado
//comparando los seqno.
//Actualiza los valores de seqno y ultima vez de las interfaces
//Luego actualiza los nuevos valores de metricas de acuerdo a diferentes condiciones
//llamando al metodo batadv_v_forward_penalty 
//Se retorna 1 si el paquete OGM es nuevo, 0 si es valido pero no es nuevo 
//y menor a 0 si es error

//Es invocada en
//bat_v_ogm.c: batadv_v_ogm_process_per_outif
//batadv_v_ogm_process_per_outif recibe como parametro la informacion de la interfaz, el header ethernet, 
// OGM2, el nodo Originator y el vecino, las interfaces salientes y entrantes
//batadv_v_ogm_process_per_outif actualiza las metricas de rendimiento y reenvia el paquete. Para actualizar
//las rutas previamente necesita actualizar las metricas de rendimiento por lo que llama a batadv_v_ogm_metric_update.
// A partir de esto, actualiza las rutas y reenvia el paquete si debe hacerlo. 

//Las secuencias de llamado a batadv_v_ogm_forward son las siguientes 
//batadv_v_ogm_process_per_outif----->batadv_v_ogm_metric_update

static int batadv_v_ogm_metric_update(struct batadv_priv *bat_priv,
				      const struct batadv_ogm2_packet *ogm2,
				      struct batadv_orig_node *orig_node,
				      struct batadv_neigh_node *neigh_node,
				      struct batadv_hard_iface *if_incoming,
				      struct batadv_hard_iface *if_outgoing)
{
	//declaracion de struct para la info del originador por interfaz saliente
	struct batadv_orig_ifinfo *orig_ifinfo;
	//declaracion de struct para la info del vecino por interfaz saliente
	struct batadv_neigh_ifinfo *neigh_ifinfo = NULL;
	bool protection_started = false;
	int ret = -EINVAL;
	u32 path_throughput;
	s32 seq_diff;


	//busca y posiblemente crea un objeto orig_ifinfo a partir del nodo origen a ser consultado
	//y la interfaz por la que deberia ser enviado
	//retorna null si falla o el objeto orig_ifinfo para la interfaz saliente. El objeto es creado
	//y agregado a la lista si no existe
	//el objeto se retorna con el refcounter aumentado en 1
	orig_ifinfo = batadv_orig_ifinfo_new(orig_node, if_outgoing);
	//si se retorno null en la funcion anterior se dirige a out
	if (!orig_ifinfo)
		goto out;

	//diferencia entre el numero de secuencia del paquete ogm2 y el ultimo de la interfaz
	seq_diff = ntohl(ogm2->seqno) - orig_ifinfo->last_real_seqno;


	//cheqyea que haya vecinos(hlist_empty)
	//ademas verifica si el host se reinicio y esta entre la ventana de tiempo de proteccion
	//retorna true si debe ser ignorado o false si debe ser aceptado.
	//Para ello necesita la informacion de la interfaz, la dif entre el numero de secuencia del
	//paquete actual y el ultimo recibido, el valor maximo a considerar como no reseado 
	if (!hlist_empty(&orig_node->neigh_list) &&
	    batadv_window_protected(bat_priv, seq_diff,
				    BATADV_OGM_MAX_AGE,
				    &orig_ifinfo->batman_seqno_reset,
				    &protection_started)) {
		//se agrega log con los datos del paquete a ignorar
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Drop packet: packet within window protection time from %pM\n",
			   ogm2->orig);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Last reset: %ld, %ld\n",
			   orig_ifinfo->batman_seqno_reset, jiffies);
		//se redirige a out
		goto out;
	}

	//descarta paquetes con numero de secuencias "viejos", sin embargo acepta
	//el primer paquete despues de que un host haya sido rebooteado
	if ((seq_diff < 0) && !protection_started)
		goto out;

	//se actualizan valores de ultima vez en nodo vecino y origen y en la interfaz
	neigh_node->last_seen = jiffies;
	orig_node->last_seen = jiffies;
	orig_ifinfo->last_real_seqno = ntohl(ogm2->seqno);
	orig_ifinfo->last_ttl = ogm2->ttl;


	//busca y posiblemente crea un objeto neigh_ifinfo a partir del nodo origen a ser consultado
	//y la interfaz por la que deberia ser enviado
	//retorna null si falla o el objeto neigh_ifinfo para la interfaz saliente. El objeto es creado
	//y agregado a la lista si no existe
	//el objeto se retorna con el refcounter aumentado en 1
	neigh_ifinfo = batadv_neigh_ifinfo_new(neigh_node, if_outgoing);
	if (!neigh_ifinfo)
		goto out;


	//aplica una penalidad al la metrica de rendimiento de reenvio con paquetes 
	//OGM BATMAN V basado en las caracteristicas de la interfaz donde el paquete OGM 
	//fue recibido. Seguidamente se muestran los calculos dependiendo las interfaces 
	//salientes y entrantes
	/*	 * - throughput * 50%      if the incoming and outgoing interface are the
	 *                             same WiFi interface and the throughput is above
	 *                             1MBit/s
	 * - throughput                if the outgoing interface is the default
	 *                             interface (i.e. this OGM is processed for the
	 *                             internal table and not forwarded)
	 * - throughput * hop penalty  otherwise
	 *
	 * 
	*/
	//Devuelve la metrica de penalidad
	path_throughput = batadv_v_forward_penalty(bat_priv, if_incoming,
						   if_outgoing,
						   ntohl(ogm2->throughput));
	//actualiza el rendimiento de la interfaz vecina
	neigh_ifinfo->bat_v.throughput = path_throughput;
	//actualiza el numero de secuencia en la interfaz vecina
	neigh_ifinfo->bat_v.last_seqno = ntohl(ogm2->seqno);
	//actualizacion del ultimo ttl
	neigh_ifinfo->last_ttl = ogm2->ttl;

	if (seq_diff > 0 || protection_started)
		//se marca que el paquete es nuevo
		ret = 1;
	else
		//el paquete no es nuevo pero valido
		ret = 0;
out:
	//se chequea por que condicion se entra a la unidad out
	if (orig_ifinfo)
		//decrementa el refcounter de org_ifinfo y posiblemente lo libera
		batadv_orig_ifinfo_put(orig_ifinfo);
	if (neigh_ifinfo)
		//decrementa el refcounter de neigh_ifinfo y posiblemente lo libera
		batadv_neigh_ifinfo_put(neigh_ifinfo);

	return ret;
}

/**
 * batadv_v_ogm_route_update - update routes based on OGM
 * @bat_priv: the bat priv with all the soft interface information
 * @ethhdr: the Ethernet header of the OGM2
 * @ogm2: OGM2 structure
 * @orig_node: Originator structure for which the OGM has been received
 * @neigh_node: the neigh_node through with the OGM has been received
 * @if_incoming: the interface where this packet was received
 * @if_outgoing: the interface for which the packet should be considered
 *
 * Return: true if the packet should be forwarded, false otherwise
 */
//Recibe como parametro la interfaz con toda la informacion, el paquete OGM
//junto con el header, el nodo origen y el vecino, y la interfaz saliente y entrante
//Actualiza las rutas basadandose en el OGM recibido por parametro
//el paquete se descarta si no fue enviado por un vecino directo o si no mejora el
//rendimiento
//Si no se descarta se actualizan las rutas y se marca para reenviar
//Se retorna true o false de acuerdo a si debe reenviarse o no

//Es invocada en
//bat_v_ogm.c: batadv_v_ogm_process_per_outif
//batadv_v_ogm_process_per_outif recibe como parametro la informacion de la interfaz, el header ethernet, 
// OGM2, el nodo Originator y el vecino, las interfaces salientes y entrantes
//batadv_v_ogm_process_per_outif actualiza las metricas de rendimiento y reenvia el paquete. Para actualizar
//las rutas y saber si debe ser reenviado el paquete se llama al metodo batadv_v_ogm_route_update

//Las secuencias de llamado a batadv_v_ogm_route_update son las siguientes 
//batadv_v_ogm_process_per_outif----->batadv_v_ogm_route_update

static bool batadv_v_ogm_route_update(struct batadv_priv *bat_priv,
				      const struct ethhdr *ethhdr,
				      const struct batadv_ogm2_packet *ogm2,
				      struct batadv_orig_node *orig_node,
				      struct batadv_neigh_node *neigh_node,
				      struct batadv_hard_iface *if_incoming,
				      struct batadv_hard_iface *if_outgoing)
{
	struct batadv_neigh_node *router = NULL;
	struct batadv_orig_node *orig_neigh_node;
	struct batadv_neigh_node *orig_neigh_router = NULL;
	struct batadv_neigh_ifinfo *router_ifinfo = NULL, *neigh_ifinfo = NULL;
	u32 router_throughput, neigh_throughput;
	u32 router_last_seqno;
	u32 neigh_last_seqno;
	s32 neigh_seq_diff;
	bool forward = false;

	//se obtiene(o crea) un nodo originador a partir de la interfaz y la direccion mac
    //si no existe lo crea aca. Si falla retorna null
	orig_neigh_node = batadv_v_ogm_orig_get(bat_priv, ethhdr->h_source);
	
	//chequea que no haya errores al asignar
	if (!orig_neigh_node)
		goto out;

	//si llega aca es porque no hubo errores en la asignacion
	
	/**
	 * batadv_orig_router_get - router to the originator depending on iface
	 * @orig_node: the orig node for the router
	 * @if_outgoing: the interface where the payload packet has been received or
	 *  the OGM should be sent to
	 *
	 * Return: the neighbor which should be router for this orig_node/iface.
	 *
	 * The object is returned with refcounter increased by 1.
	 */
	// se obtiene el vecino que deberia ser ruteado por este nodo originador e interfaz
	//El objeto se retorna con el refcounter incrementado en 1
	orig_neigh_router = batadv_orig_router_get(orig_neigh_node,
						   if_outgoing);

	/* drop packet if sender is not a direct neighbor and if we
	 * don't route towards it
	 */
	router = batadv_orig_router_get(orig_node, if_outgoing);
	if (router && router->orig_node != orig_node && !orig_neigh_router) {
		//se agrega el log informando que el paquete no fue enviado por un vecino directo
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Drop packet: OGM via unknown neighbor!\n");
		goto out;
	}


	//Se marca el paquete OGM a ser considerado para reenviar y actualiza las rutas
	//si es necesario
	forward = true;

	//se agrega log 
	batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
		   "Searching and updating originator entry of received packet\n");


	//Si ese vecino ya es el siguiente salto no hay nada que cambiar
	if (router == neigh_node)
		goto out;

	/* don't consider neighbours with worse throughput.
	 * also switch route if this seqno is BATADV_V_MAX_ORIGDIFF newer than
	 * the last received seqno from our best next hop.
	 */
	if (router) {
		// encuentra la ifinfo de un nodo vecino a partir de el nodo a ser consultado(router)
		// y la interfaz por la cual se debe adquirir ifinfo
		router_ifinfo = batadv_neigh_ifinfo_get(router, if_outgoing);

		// encuentra la ifinfo de un nodo vecino a partir de el nodo a ser consultado(neigh_node)
		// y la interfaz por la cual se debe adquirir ifinfo	
		neigh_ifinfo = batadv_neigh_ifinfo_get(neigh_node, if_outgoing);

		/* if these are not allocated, something is wrong. */
		if (!router_ifinfo || !neigh_ifinfo)
			goto out;

		neigh_last_seqno = neigh_ifinfo->bat_v.last_seqno;
		router_last_seqno = router_ifinfo->bat_v.last_seqno;
		neigh_seq_diff = neigh_last_seqno - router_last_seqno;
		router_throughput = router_ifinfo->bat_v.throughput;
		neigh_throughput = neigh_ifinfo->bat_v.throughput;

		//se chequa que la distancia entre el numero de secuencia de 
		//neigh_last_seqno y router_last_seqno no sea mayor a BATADV_OGM_MAX_ORIGDIFF(5) 
		//si el throughput de router es mayor que el del vecino se redirige a out
		if ((neigh_seq_diff < BATADV_OGM_MAX_ORIGDIFF) &&
		    (router_throughput >= neigh_throughput))
			goto out;
	}

	/**
	 * batadv_update_route - set the router for this originator
	 * @bat_priv: the bat priv with all the soft interface information
	 * @orig_node: orig node which is to be configured
	 * @recv_if: the receive interface for which this route is set
	 * @neigh_node: neighbor which should be the next router
	 */
	batadv_update_route(bat_priv, orig_node, if_outgoing, neigh_node);
out:
	//chequa por que condicion entro
	if (router)
		//decrementa el refcounter de los vecinos de router y posiblemente los libera
		batadv_neigh_node_put(router);
	if (orig_neigh_router)
		//decrementa el refcounter de los vecinos de orig_neigh_router y posiblemente los libera
		batadv_neigh_node_put(orig_neigh_router);
	if (orig_neigh_node)
		//decrementa el refcounter de los vecinos de orig_neigh_node y posiblemente los libera
		batadv_orig_node_put(orig_neigh_node);
	if (router_ifinfo)
		//decrementa el refcounter del objeto router_ifinfo y posiblemente los libera
		batadv_neigh_ifinfo_put(router_ifinfo);
	if (neigh_ifinfo)
		//decrementa el refcounter del objeto router_ifinfo y posiblemente los libera
		batadv_neigh_ifinfo_put(neigh_ifinfo);

	//return true o false dependiendo si fue reenviado o no
	return forward;
}

/**
 * batadv_v_ogm_process_per_outif - process a batman v OGM for an outgoing if
 * @bat_priv: the bat priv with all the soft interface information
 * @ethhdr: the Ethernet header of the OGM2
 * @ogm2: OGM2 structure
 * @orig_node: Originator structure for which the OGM has been received
 * @neigh_node: the neigh_node through with the OGM has been received
 * @if_incoming: the interface where this packet was received
 * @if_outgoing: the interface for which the packet should be considered
 */
//batadv_v_ogm_process_per_outif recibe como parametro la informacion de la interfaz, el header ethernet, 
// OGM2, el nodo Originator y el vecino, las interfaces salientes y entrantes
//batadv_v_ogm_process_per_outif actualiza las metricas de rendimiento y reenvia el paquete

//Es invocada en
//bat_v_ogm.c: batadv_v_ogm_process
//batadv_v_ogm_process es invocada para procesar un paquete OGM.
//Si el paquete no es decartado, se debe actualizar las metricas de rendimiento y procesarlo 
//por una interfaz saliente, para ello se invoca esta funcion(batadv_v_ogm_process_per_outif)

//Las secuencias de llamado a batadv_v_ogm_process_per_outif son las siguientes 
//batadv_v_ogm_process----->batadv_v_ogm_process_per_outif

static void
batadv_v_ogm_process_per_outif(struct batadv_priv *bat_priv,
			       const struct ethhdr *ethhdr,
			       const struct batadv_ogm2_packet *ogm2,
			       struct batadv_orig_node *orig_node,
			       struct batadv_neigh_node *neigh_node,
			       struct batadv_hard_iface *if_incoming,
			       struct batadv_hard_iface *if_outgoing)
{
	int seqno_age;
	bool forward;

	/* first, update the metric with according sanity checks */
	seqno_age = batadv_v_ogm_metric_update(bat_priv, ogm2, orig_node,
					       neigh_node, if_incoming,
					       if_outgoing);

	//los números de secuencia obsoletos deben descartarse
	if (seqno_age < 0)
		return;

	/* only unknown & newer OGMs contain TVLVs we are interested in */
	if ((seqno_age > 0) && (if_outgoing == BATADV_IF_DEFAULT))
		/**
		 * batadv_tvlv_containers_process - parse the given tvlv buffer to call the
		 *  appropriate handlers
		 * @bat_priv: the bat priv with all the soft interface information
		 * @ogm_source: flag indicating whether the tvlv is an ogm or a unicast packet
		 * @orig_node: orig node emitting the ogm packet
		 * @src: source mac address of the unicast packet
		 * @dst: destination mac address of the unicast packet
		 * @tvlv_value: tvlv content
		 * @tvlv_value_len: tvlv content length
		 *
		 * Return: success when processing an OGM or the return value of all called
		 * handler callbacks.
		 */
		batadv_tvlv_containers_process(bat_priv, true, orig_node,
					       NULL, NULL,
					       (unsigned char *)(ogm2 + 1),
					       ntohs(ogm2->tvlv_len));

	/* if the metric update went through, update routes if needed */
	forward = batadv_v_ogm_route_update(bat_priv, ethhdr, ogm2, orig_node,
					    neigh_node, if_incoming,
					    if_outgoing);

	/* if the routes have been processed correctly, check and forward */
	if (forward)
		batadv_v_ogm_forward(bat_priv, ogm2, orig_node, neigh_node,
				     if_incoming, if_outgoing);
}

/**
 * batadv_v_ogm_aggr_packet - checks if there is another OGM aggregated
 * @buff_pos: current position in the skb
 * @packet_len: total length of the skb
 * @tvlv_len: tvlv length of the previously considered OGM
 *
 * Return: true if there is enough space for another OGM, false otherwise.
 */
//batadv_v_ogm_aggr_packet recibe como parametro la posicion actual en el buffer, la longitud total del buffer
//y la longitud tvlv del OGM considerado previamente
//Chequea si existe otro OGM en el buffer sea porque la longitud actual es menor a la longitud del buffer
//o porque no supero el maximo de bytes

//Es invocada en
//bat_v_ogm.c: batadv_v_ogm_packet_recv
// batadv_v_ogm_packet_recv utiliza como condicion de loop para procesar cada paquete OGM que esta en el buffer.
//Mientras batadv_v_ogm_aggr_packet sea true significa que hay mas OGMs para procesar.

//Las secuencias de llamado a batadv_v_ogm_aggr_packet son las siguientes 
//batadv_v_ogm_packet_recv----->batadv_v_ogm_aggr_packet

//batadv_v_ogm_aggr_packet se publica en bat_v_ogm.h
static bool batadv_v_ogm_aggr_packet(int buff_pos, int packet_len,
				     __be16 tvlv_len)
{
	//inicializacion de variable
	int next_buff_pos = 0;

	//actualiza con la posicion actual en el buffer sumando el tamaño de otro paquete
	next_buff_pos += buff_pos + BATADV_OGM2_HLEN;
	next_buff_pos += ntohs(tvlv_len);

	//return true si hay espacio para otro OGM, sino retorna false
	return (next_buff_pos <= packet_len) &&
	       (next_buff_pos <= BATADV_MAX_AGGREGATION_BYTES);
}

/**
 * batadv_v_ogm_process - process an incoming batman v OGM
 * @skb: the skb containing the OGM
 * @ogm_offset: offset to the OGM which should be processed (for aggregates)
 * @if_incoming: the interface where this packet was receved
 */

//batadv_v_ogm_process recibe como parametro el socket buffer, el offset del ogm y la interfaz entrante. 
// se encarga de un paquete OGM recibido a partir de una interfaz, el buffer y el offset pasados por parametro.
// Hace diferentes controles para chequear si debe descartar el paquete o procesarlo. Por ejemplo si la metrica
//es cero, si no hay vecinos, etc.
//Procesarlo implica actualizar la metrica de rendimiento, chequear si es necesario realizar broadcast,
//y procesar el paquete por la interfaz saliente. 
// Tambien se decrementa el contador de referencia de la interfaz y posiblemente se libera la memoria

//Es invocada en
//bat_v_ogm.c: batadv_v_ogm_packet_recv
// batadv_v_ogm_packet_recv se encarga de manenar los paquetes OGM recibidos a partir de una interfaz y 
// un paquete OGM pasada por parametro.
// Si no existe algun error o la mac origen del paquete no pertenece a la mesh se procesa 
// llamando al metodo batadv_v_ogm_process
// batadv_v_ogm_packet_recv utiliza a batadv_v_ogm_process por cada paquete OGM que esta en el buffer. 

//Las secuencias de llamado a batadv_v_ogm_process son las siguientes 
//batadv_v_ogm_packet_recv----->batadv_v_ogm_process
static void batadv_v_ogm_process(const struct sk_buff *skb, int ogm_offset,
				 struct batadv_hard_iface *if_incoming)
{
	//datos de la interfaz entrante
	struct batadv_priv *bat_priv = netdev_priv(if_incoming->soft_iface);
	//inicializacion de variables
	struct ethhdr *ethhdr;
	struct batadv_orig_node *orig_node = NULL;
	struct batadv_hardif_neigh_node *hardif_neigh = NULL;
	struct batadv_neigh_node *neigh_node = NULL;
	struct batadv_hard_iface *hard_iface;
	struct batadv_ogm2_packet *ogm_packet;
	u32 ogm_throughput, link_throughput, path_throughput;
	int ret;

	ethhdr = eth_hdr(skb);
	ogm_packet = (struct batadv_ogm2_packet *)(skb->data + ogm_offset);

	ogm_throughput = ntohl(ogm_packet->throughput);

	//Agrega log informando que recibió un paquete OGM a prcesar con informacion de la interfaz 
	// e informacion del paquete como throughput, ttl, version, etc 
	batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
		   "Received OGM2 packet via NB: %pM, IF: %s [%pM] (from OG: %pM, seqno %u, troughput %u, TTL %u, V %u, tvlv_len %u)\n",
		   ethhdr->h_source, if_incoming->net_dev->name,
		   if_incoming->net_dev->dev_addr, ogm_packet->orig,
		   ntohl(ogm_packet->seqno), ogm_throughput, ogm_packet->ttl,
		   ogm_packet->version, ntohs(ogm_packet->tvlv_len));

	 
	 //si el throughput es cero se descarta el paquete y termina el procedimiento
	//tambien se agrega un log informando que la metrica throughput es cero 
	//no hay necesidad de seguir procesando ya que la ruta es inutilizable
	if (ogm_throughput == 0) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Drop packet: originator packet with troughput metric of 0\n");
		return;
	}

	/* require ELP packets be to received from this neighbor first */
	//si llega aca es porque la metrica no es cero.
	//requiere recibir paquetes ELP de sus vecinos primero. 
	//La funcion devuelve un vecino por la interfaz entrante   
	hardif_neigh = batadv_hardif_neigh_get(if_incoming, ethhdr->h_source);

	//chequa si hay vecinos
	//si no hay descarta el paquete y crea un log con esta informacion
	if (!hardif_neigh) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Drop packet: OGM via unknown neighbor!\n");
		goto out;
	}

	//si pasa es poruqe existe un vecino
	 
	//En orig_node se guarda o crea un originator node a partir de la interfaz
	// y la direccion del originator
	orig_node = batadv_v_ogm_orig_get(bat_priv, ogm_packet->orig);
	//si orig_node hay un null es porque hubo fallas de asignacion y termina el metodo 
	if (!orig_node)
		return;


	//recupera o crea un nodo vecino a partir del nodo origen, la inferfaz entrante y la mac
	//si no lo encuentra o no lo puede crear devuelve null
	neigh_node = batadv_neigh_node_get_or_create(orig_node, if_incoming,
						     ethhdr->h_source);
	//si es null entra al if se redirige  
	if (!neigh_node)
		goto out;

	//si llega aca es porque neigh_node tiene un nodo  con la info de vecinos


	//Actualiza la metrica de throughput recibida para que coincida con las caracteristicas
	//del enlace:
	// - Si el paquete OGM fue emitido por un vecino la metrica de rendimiento del camino es igual 
	//a la del enlace
	// - Para los OGMs que atraviesan mas de un salto, la metrica de rendimiento del camino es la
	// mas pequeña del rendimiento del camino y del enlace
	link_throughput = ewma_throughput_read(&hardif_neigh->bat_v.throughput);
	path_throughput = min_t(u32, link_throughput, ogm_throughput);
	ogm_packet->throughput = htonl(path_throughput);

	/**
	 * batadv_v_ogm_process_per_outif - process a batman v OGM for an outgoing if
	 * @bat_priv: the bat priv with all the soft interface information
	 * @ethhdr: the Ethernet header of the OGM2
	 * @ogm_packet: OGM2 structure
	 * @orig_node: Originator structure for which the OGM has been received
	 * @neigh_node: the neigh_node through with the OGM has been received
	 * @if_incoming: the interface where this packet was received
	 * @BATADV_IF_DEFAULT: the interface for which the packet should be considered
	 */
	//procesa un batman v OGM para un interfaz saliente
	batadv_v_ogm_process_per_outif(bat_priv, ethhdr, ogm_packet, orig_node,
				       neigh_node, if_incoming,
				       BATADV_IF_DEFAULT);

	//Kernel function. mark the beginning of an RCU read-side critical section
	rcu_read_lock();
	
	
	//Macro que itera sobre la lista rcu.
	//Se corre concurrentemente las entradas( por eso la sentencia anterior
	// para manejar la concurrencia)
	list_for_each_entry_rcu(hard_iface, &batadv_hardif_list, list) {
		//si la interfaz no esta activa entra al if
		if (hard_iface->if_status != BATADV_IF_ACTIVE)
			//Fuerza a que comience una nueva vuelta dentro del ciclo
			continue;

		//si ambas interfaces son distintas entra al if
		if (hard_iface->soft_iface != bat_priv->soft_iface)
			//Fuerza a que comience una nueva vuelta dentro del ciclo	
			continue;


		if (!kref_get_unless_zero(&hard_iface->refcount))
			//Fuerza a que comience una nueva vuelta dentro del ciclo
			continue;



		//chequea si es necesario (re)enviar por broadcast
		//se pasa hard_iface que es la interface de salida
		// ogm_packet->orig el paquete de origen a ser retrasmitido
		//hardif_neigh->orig la direccion del originador de quien envia
		ret = batadv_hardif_no_broadcast(hard_iface,
						 ogm_packet->orig,
						 hardif_neigh->orig);

		//analiza el valor de ret ya que puede ser:
		/**
		 *	BATADV_HARDIF_BCAST_NORECIPIENT: Sin vecino o interfaz
		 *	BATADV_HARDIF_BCAST_DUPFWD: Solo un vecino pero es quien despachó el paquete
		 *	BATADV_HARDIF_BCAST_DUPORIG: Solo un vecino pero es quien creo el paquete(originator)
		 *	BATADV_HARDIF_BCAST_OK: Muchos vecinos, debe trasmitirse por broadcast
		 */
		if (ret) {
			//se actualiza el tipo de acuerto al valor de ret
			char *type;
			switch (ret) {
			case BATADV_HARDIF_BCAST_NORECIPIENT:
				type = "no neighbor";
				break;
			case BATADV_HARDIF_BCAST_DUPFWD:
				type = "single neighbor is source";
				break;
			case BATADV_HARDIF_BCAST_DUPORIG:
				type = "single neighbor is originator";
				break;
			default:
				type = "unknown";
			}

			//se agrega un log con la informacion del paquete y el tipo
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv, "OGM2 packet from %pM on %s surpressed: %s\n",
				   ogm_packet->orig, hard_iface->net_dev->name,
				   type);


			//decrementa el refcounter de hard_iface y posiblemente lo libera
 			batadv_hardif_put(hard_iface);
			//avanza al siguiente loop
			continue;
		}

		//procesa un paquete OGM por una interfaz saliente para eso pasa por parametro
		//bat_priv con la informacion de la interfaz
		//el header ethernet del OGM2
		//el nodo origen y vecino por el cual ha sido, 
		//y la interfaz por la cual el paquete deberia ser considerado
 		batadv_v_ogm_process_per_outif(bat_priv, ethhdr, ogm_packet,
					       orig_node, neigh_node,
					       if_incoming, hard_iface);

		/**
		 * batadv_hardif_put - decrement the hard interface refcounter and possibly
		 *  release it
		 * @hard_iface: the hard interface to free
		 */
 		//decrement the hard interface refcounter and possibly
		// release it
 		batadv_hardif_put(hard_iface);
	}
	//Kernel function. Marks the end of an RCU read-side critical section.
	rcu_read_unlock();
out: 
	//chequea por que condicion llego al out para decrementar el refcounter 
	if (orig_node)
		 // batadv_orig_node_put - decrement the orig node refcounter and possibly
		 //  release it
		batadv_orig_node_put(orig_node);
	if (neigh_node)
		
		 // batadv_neigh_node_put - decrement the neighbors refcounter and possibly
		 //  release it
		batadv_neigh_node_put(neigh_node);
	if (hardif_neigh)
		 // batadv_hardif_neigh_put - decrement the hardif neighbors refcounter
		 //  and possibly release it
		 batadv_hardif_neigh_put(hardif_neigh);
}

/**
 * batadv_v_ogm_packet_recv - OGM2 receiving handler
 * @skb: the received OGM
 * @if_incoming: the interface where this OGM has been received
 *
 * Return: NET_RX_SUCCESS and consume the skb on success or returns NET_RX_DROP
 * (without freeing the skb) on failure
 */

// batadv_v_ogm_packet_recv recibe como parametro el socket buffer y la interfaz entrante. 
// se encarga de manenar los paquetes OGM recibidos a partir de una interfaz y un paquete OGM pasada por parametro.
// Si existe algun error o la mac origen del paquete pertenece a la mesh se descarta el paquete sino se procesa 
// llamando al metodo batadv_v_ogm_process

//Es invocada en
//bat_v.c: batadv_v_init
//batadv_v_init  no recibe parametros. Su tarea es inicializar todos los subcomponentes 
//entre ellos los handler de los registros de paquetes OGM y ELP.

//Las secuencias de llamado a batadv_v_ogm_packet_recv son las siguientes 
//batadv_v_init----->batadv_v_ogm_packet_recv

//batadv_v_ogm_packet_recv se publica en bat_v_ogm.h
int batadv_v_ogm_packet_recv(struct sk_buff *skb,
			     struct batadv_hard_iface *if_incoming)
{

	struct batadv_priv *bat_priv = netdev_priv(if_incoming->soft_iface);
	//se crea un paquete OGM
	struct batadv_ogm2_packet *ogm_packet;
	//se crea un frame ethernet
	struct ethhdr *ethhdr = eth_hdr(skb);
	int ogm_offset;
	u8 *packet_pos;
	int ret = NET_RX_DROP;

	/* did we receive a OGM2 packet on an interface that does not have
	 * B.A.T.M.A.N. V enabled ?
	 */
	// chequea si se recibio un paquete OGM2 en una interfaz que no tiene 
	//B.A.T.M.A.N v habilitado.
	//Si no lo tiene habilitado entra al if y se libera el buffer
	if (strcmp(bat_priv->algo_ops->name, "BATMAN_V") != 0)
		goto free_skb;

	//Si llega aca es porque tiene B.A.T.M.A.N V habilitado 
	// Chequea si el paquete recibido no esta mal
	//si hay fallas en el paquete entra al if y se libera tambien el buffer
	if (!batadv_check_management_packet(skb, if_incoming, BATADV_OGM2_HLEN))
		goto free_skb;

	
	//si llega aca es porque el paquete es correcto y la interfaz tiene B.A.T.M.A.N V  habilitado.
	//Se chequea si la direccion mac de la direccion origen del frame pertenece a algunas de las interfaces de la mesh actual
	//si sucede lo anterior se libera el buffer.
 	if (batadv_is_my_mac(bat_priv, ethhdr->h_source))
		goto free_skb;

	//si se llega aca el frame ethernet no fue enviado por un vecino
	//se lee un paquete OGM del buffer
	ogm_packet = (struct batadv_ogm2_packet *)skb->data;

	/**
	 * batadv_is_my_mac - check if the given mac address belongs to any of the real
	 * interfaces in the current mesh
	 * @bat_priv: the bat priv with all the soft interface information
	 * @ogm_packet->orig: the address to check
	 *
	 * Return: 'true' if the mac address was found, false otherwise.
	 */

	//Se chequea si la direccion mac de la direccion origen del paquete leido del buffer
	// pertenece a algunas de las interfaces de la mesh actual
	//si sucede lo anterior se libera el buffer.
	if (batadv_is_my_mac(bat_priv, ogm_packet->orig))
		goto free_skb;

	// incrementa el contador de trafico de paquetes protocol routing de la mesh
	batadv_inc_counter(bat_priv, BATADV_CNT_MGMT_RX);
	// incrementa la cantidad de bytes de trafico de paquetes protocol routing de la mesh
	batadv_add_counter(bat_priv, BATADV_CNT_MGMT_RX_BYTES,
			   skb->len + ETH_HLEN);

	//setea offset de ogm en cero
	ogm_offset = 0;
	//obtiene el paquete OGM del frame ethernet
	ogm_packet = (struct batadv_ogm2_packet *)skb->data;

	/**
	 * batadv_v_ogm_aggr_packet - checks if there is another OGM aggregated
	 * @ogm_offset: current position in the skb
	 * @skb_headlen(skb): total length of the skb
	 * @ogm_packet->tvlv_len: tvlv length of the previously considered OGM
	 *
	 * Return: true if there is enough space for another OGM, false otherwise.
	 */
	//loop o recorrido de cada paquete OGM 
 	while (batadv_v_ogm_aggr_packet(ogm_offset, skb_headlen(skb),
					ogm_packet->tvlv_len)) {
		/**
		 * batadv_v_ogm_process - process an incoming batman v OGM
		 * @skb: the skb containing the OGM
		 * @ogm_offset: offset to the OGM which should be processed (for aggregates)
		 * @if_incoming: the interface where this packet was receved
		 */
 		// se procesa el paquete OGM de la interfaz entrante 
 		batadv_v_ogm_process(skb, ogm_offset, if_incoming);

 		//se actualiza los offsets para avanzar en la skb
		ogm_offset += BATADV_OGM2_HLEN;
		ogm_offset += ntohs(ogm_packet->tvlv_len);

		packet_pos = skb->data + ogm_offset;
		ogm_packet = (struct batadv_ogm2_packet *)packet_pos;
	}

	// NET_RX_SUCCESS es 0 y significa que no hubo errores
 	ret = NET_RX_SUCCESS;

free_skb:
	//Si no tiene el BATMAN V habilitado, si hay fallas en el paquete, si el paquete fue enviado por un vecino
	// entra aca y se libera el paquete
	if (ret == NET_RX_SUCCESS)
		consume_skb(skb);
	else
		kfree_skb(skb);

	// return NET_RX_SUCCESS (0) si no hubo errores. Sino retorna NET_RX_DROP
	return ret;
}

/**
 * batadv_v_ogm_init - initialise the OGM2 engine
 * @bat_priv: the bat priv with all the soft interface information
 *
 * Return: 0 on success or a negative error code in case of failure
 */

//En cada interfaz batman de un nodo, se almacena informacion de varios tipos.
// batadv_v_ogm_init se encarga de inicializar el buffer OGM y la workqueue preparando
// un paquete OGM inicial
//retorna 0 si no hay problemas, o el numero de error si falla al asignar memoria 

//Es invocada en
//bat_v.c: batadv_v_mesh_init
//  batadv_v_mesh_init recibe por parametro una mesh interface con toda su informacion,
// donde se inicializan todos los recursos privados para una mesh y para ello se utiliza 
 // batadv_v_ogm_init

//Las secuencias de llamado a batadv_v_ogm_init son las siguientes 
//batadv_v_mesh_init----->batadv_v_ogm_init

//batadv_v_ogm_free se publica en bat_v_ogm.h
int batadv_v_ogm_init(struct batadv_priv *bat_priv)
{
	// definicion de un paquete ogm2 (routing protocol)
	struct batadv_ogm2_packet *ogm_packet;
	unsigned char *ogm_buff;
	u32 random_seqno;

	// inicializacion de la longitud del buffer con el tamaño de un paquete definido 
	// por la siguiente macro sizeof(struct batadv_ogm2_packet)
	bat_priv->bat_v.ogm_buff_len = BATADV_OGM2_HLEN;
	// funcion del kernel para asignar memoria. La memoria está configurada en cero.
	ogm_buff = kzalloc(bat_priv->bat_v.ogm_buff_len, GFP_ATOMIC);
	// si hay un error al asignar memoria se retorna el error correspondiente a fuera de memoria
	if (!ogm_buff)
		return -ENOMEM;

	//si llega aca es porque se realizo correctamente el pedido de memoria
	//asignacion del buffer creado al de la inteface pasada por parametro
	//Inicializacion del paquete OGM declarado en la funcion con valores iniciales
	bat_priv->bat_v.ogm_buff = ogm_buff;
	ogm_packet = (struct batadv_ogm2_packet *)ogm_buff;
	ogm_packet->packet_type = BATADV_OGM2;
	ogm_packet->version = BATADV_COMPAT_VERSION;
	ogm_packet->ttl = BATADV_TTL;
	ogm_packet->flags = BATADV_NO_FLAGS;
	ogm_packet->throughput = htonl(BATADV_THROUGHPUT_MAX_VALUE);

	/* randomize initial seqno to avoid collision */
	get_random_bytes(&random_seqno, sizeof(random_seqno));
	//seteo del valor obtenido en la sentencia anterior
	atomic_set(&bat_priv->bat_v.ogm_seqno, random_seqno);
	//se setea timer y tflags para iniciar el envio de OGMs
	INIT_DELAYED_WORK(&bat_priv->bat_v.ogm_wq, batadv_v_ogm_send);

	return 0;
}

/**
 * batadv_v_ogm_free - free OGM private resources
 * @bat_priv: the bat priv with all the soft interface information
 */

//En cada interfaz batman de un nodo, se almacena informacion de varios tipos.
//Entre esa informacion se almacena el buffer de los paquetes ogm junto con la cola de trabajo de los paquetes
// OGM
//Esta funcion (batadv_v_ogm_free) recibe una interfaz, y se encarga de liberar la memoria del buffer OGM
//y setear los valores iniciales

//Es invocada en
//bat_v.c: batadv_v_mesh_free
//  batadv_v_mesh_free recibe por parametro una mesh interface, para la cual la unica funcionalidad es llamar 
// a batadv_v_ogm_free donde se liberan los recursos privados de los paquetes OGM de la interface

//Las secuencias de llamado a batadv_v_ogm_free son las siguientes 
//batadv_v_mesh_free----->batadv_v_ogm_free

//batadv_v_ogm_free se publica en bat_v_ogm.h
void batadv_v_ogm_free(struct batadv_priv *bat_priv)
{
	/**
	 * cancel_delayed_work_sync - cancel a delayed work and wait for it to finish
	 * @dwork: the delayed work cancel
	 *
	 * This is cancel_work_sync() for delayed works.
	 *
	 * Return:
	 * %true if @dwork was pending, %false otherwise.
	 */
	// cancela los trabajos retrasados de la workqueue
	//retornando true si habia trabajos pendientes o false en caso contrario	 
 	cancel_delayed_work_sync(&bat_priv->bat_v.ogm_wq);

	//funcion del kernel para liberar la memoria del buffer OGM
	kfree(bat_priv->bat_v.ogm_buff);
	//Inicializa los valores del buffer en vacio
	bat_priv->bat_v.ogm_buff = NULL;
	bat_priv->bat_v.ogm_buff_len = 0;
}
