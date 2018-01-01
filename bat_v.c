/* Copyright (C) 2013-2017  B.A.T.M.A.N. contributors:
 *
 * Linus Lüssing, Marek Lindner
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

#include "bat_v.h"
#include "main.h"

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/cache.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include <uapi/linux/batman_adv.h>

#include "bat_algo.h"
#include "bat_v_elp.h"
#include "bat_v_ogm.h"
#include "gateway_client.h"
#include "gateway_common.h"
#include "hard-interface.h"
#include "hash.h"
#include "log.h"
#include "netlink.h"
#include "originator.h"
#include "packet.h"

struct sk_buff;

//Activacion de la interfaz pasada por parametro.
//Se actualiza  el buffer de la interfaz para mensajes ELP
//Por ultimo si la interfaz tiene el estado BATADV_IF_TO_BE_ACTIVATED 
//se cambia a BATADV_IF_ACTIVE

//No es invocada en metodos
static void batadv_v_iface_activate(struct batadv_hard_iface *hard_iface)
{
	//se obtiene la informacion de la mesh
	struct batadv_priv *bat_priv = netdev_priv(hard_iface->soft_iface);
	struct batadv_hard_iface *primary_if;
	pr_info("Entro a batadv_v_iface_activate: interfaz numero %i\n", hard_iface->if_num);
	//se obtiene la interfaz primaria
	primary_if = batadv_primary_if_get_selected(bat_priv);

	if (primary_if) {
		/**
		 * batadv_v_elp_iface_activate - update the ELP buffer belonging to the given
		 *  hard-interface
		 * @primary_iface: the new primary interface
		 * @hard_iface: interface holding the to-be-updated buffer
		 */
		//Actualiza el buffer ELP perteneciente a la interfaz hard_iface
		batadv_v_elp_iface_activate(primary_if, hard_iface);
		//reduce el refcounter de primary_if y posiblemente la libera
		batadv_hardif_put(primary_if);
	}

	/* B.A.T.M.A.N. V does not use any queuing mechanism, therefore it can
	 * set the interface as ACTIVE right away, without any risk of race
	 * condition
	 */
	//Cambio de estado de la intefaz
	if (hard_iface->if_status == BATADV_IF_TO_BE_ACTIVATED)
		hard_iface->if_status = BATADV_IF_ACTIVE;
}

//Activa los recursos privados de la interfaz ELP y OGM.
//Devuelve 0 o numero de error(valor negativo). El error puede ser por
//habilitar la interfaz ELP o OGM
//si hay error no puede quedar habilitadas ninguna de las dos

//No es invocada en metodos
static int batadv_v_iface_enable(struct batadv_hard_iface *hard_iface)
{
	int ret;

	//Activa los recursos privados de la interfaz ELP.
	//ret toma 0 si no hay problemas o -ENOMEN en caso de fallos 
	ret = batadv_v_elp_iface_enable(hard_iface);
	//Si hay error se retorna el numero de error(-ENOMEN)
	if (ret < 0)
		return ret;

	//si llega aca es porque no hubo error

	//La tarea de esta funcion es reiniciar el timer de envio de paquetes OGM
	//para ello necesita la informacion de la interfaz pero principalmente su cola 
	//de trabajo
	// Esta funcion puede ser invocada para replanificar un envio de ogm o 
	// para activar una interfaz. En este caso se llama para activar la interfaz
	ret = batadv_v_ogm_iface_enable(hard_iface);
	//Si hay error se deshabilita la interfaz para mensajes ELP
	if (ret < 0)
		//liberar recursos privados de la interfaz ELP
		batadv_v_elp_iface_disable(hard_iface);

	//Devuelve 0 o numero de error(valor negativo)
	return ret;
}
//Se pasa por parametro la interfaz a ser deshabilitada
//Implica deshabilitar o liberar recursos privados de la interfaz ELP

//No es invocada en metodos
static void batadv_v_iface_disable(struct batadv_hard_iface *hard_iface)
{
	//liberar recursos privados de la interfaz ELP
	batadv_v_elp_iface_disable(hard_iface);
}

//Setea una interfaz primaria para mensajes ELP y  OGM. Ambas funcionalidades
//estan divididas cada uno en distintos metodos y cada uno en su archivo .c

//Es invocada en
//bat_v.c: batadv_v_iface_update_mac

//Las secuencias de llamado a batadv_v_primary_iface_set son las siguientes 
//batadv_v_iface_update_mac----->batadv_v_primary_iface_set

static void batadv_v_primary_iface_set(struct batadv_hard_iface *hard_iface)
{
	
	//Setea una interfaz primaria. Para ello, cambia los datos internos 
	batadv_v_elp_primary_iface_set(hard_iface);
	//Setea una interfaz primaria. Antes chequea que haya paquetes en el buffer sino 
	//termina la ejecucion de la funcion.
	//si hay paquetes copia la direccion ethernet de la interfaz al paquete 
	batadv_v_ogm_primary_iface_set(hard_iface);
}

/**
 * batadv_v_iface_update_mac - react to hard-interface MAC address change
 * @hard_iface: the modified interface
 *
 * If the modified interface is the primary one, update the originator
 * address in the ELP and OGM messages to reflect the new MAC address.
 */

//A partir de una interfaz pasada por parametro se cambia la direccion mac
//Si la interfaz pasada por parametro es la primaria, se actualiza la direccion de
//origen en los mensajes ELP y OGM para reflejar la nueva direccion MAC 

//No es invocada en metodos
static void batadv_v_iface_update_mac(struct batadv_hard_iface *hard_iface)
{
	//se obtiene la informacion de la mesh
	struct batadv_priv *bat_priv = netdev_priv(hard_iface->soft_iface);
	struct batadv_hard_iface *primary_if;
	//Se obtiene la interfaz principal
	primary_if = batadv_primary_if_get_selected(bat_priv);
	//Si la interfaz pasada por parametro y la primaria son distintas no se actualizan
	// la direccion de los paquetes
	//Se redirige a out
	if (primary_if != hard_iface)
		goto out;

	//Setea una interfaz primaria para mensajes ELP y  OGM. Ambas funcionalidades
	//estan divididas cada uno en distintos metodos y cada uno en su archivo .c
	batadv_v_primary_iface_set(hard_iface);
out:
	if (primary_if)
		//reduce el refcounter de primary_if y posiblemente la libera
		batadv_hardif_put(primary_if);
}


//Inicializacion de redimiento de los vecinos
//No es invocada en metodos
static void
batadv_v_hardif_neigh_init(struct batadv_hardif_neigh_node *hardif_neigh)
{
	ewma_throughput_init(&hardif_neigh->bat_v.throughput);
	INIT_WORK(&hardif_neigh->bat_v.metric_work,
		  batadv_v_elp_throughput_metric_update);
}

#ifdef CONFIG_BATMAN_ADV_DEBUGFS
/**
 * batadv_v_orig_print_neigh - print neighbors for the originator table
 * @orig_node: the orig_node for which the neighbors are printed
 * @if_outgoing: outgoing interface for these entries
 * @seq: debugfs table seq_file struct
 *
 * Must be called while holding an rcu lock.
 */

//Imprime la "originator table" del nodo orig_node pasado por parametro
//Los campos de la tabla son la direccion mac del nodo, su throughput / 10
//y el 10 % de su throughput  

//Es invocada en
//bat_v.c: batadv_v_orig_print
//Este metodo imprime la "originator table"
//Recorre concurrentemente la hash del nodo origen . Por cada vecino 
//imprime nodo origen, ultimo visto en segundos y milisegundos, 
//rendimiento / 10 con su resto, direccion mac del vecino
// y el nombre de la interfaz entrante

//Las secuencias de llamado a batadv_v_orig_print_neigh son las siguientes 
//batadv_v_orig_print----->batadv_v_orig_print_neigh

static void
batadv_v_orig_print_neigh(struct batadv_orig_node *orig_node,
			  struct batadv_hard_iface *if_outgoing,
			  struct seq_file *seq)
{
	struct batadv_neigh_node *neigh_node;
	struct batadv_neigh_ifinfo *n_ifinfo;

	//macro que recorre la lista de vecinos concurrentemente
	hlist_for_each_entry_rcu(neigh_node, &orig_node->neigh_list, list) {
		//Encuentra la ifinfo del nodo neigh_node o null si no la encuentra
		//El objeto se devuelve con refcount aumentado en 1
		n_ifinfo = batadv_neigh_ifinfo_get(neigh_node, if_outgoing);
		
		//Verifica n_ifinfo no sea null
		if (!n_ifinfo)
			continue;

		//si llega aca es porque no es null
		//print la direccion del nodo, su throughput / 10
		//y el resto de la division  
		seq_printf(seq, " %pM (%9u.%1u)",
			   neigh_node->addr,
			   n_ifinfo->bat_v.throughput / 10,
			   n_ifinfo->bat_v.throughput % 10);

		//reduce el refcounter de n_ifinfo y posiblemente la libera
		batadv_neigh_ifinfo_put(n_ifinfo);
	}
}

/**
 * batadv_v_hardif_neigh_print - print a single ELP neighbour node
 * @seq: neighbour table seq_file struct
 * @hardif_neigh: hardif neighbour information
 */
//imprime un nodo vecino ELP. Los datos que imprimen son:
// direccion mac, ultimo visto en segundos y milisegundos, 
//rendimiento / 10 con su resto y el nombre de la interfaz entrante

//Es invocada por:
//batman_v.c: batadv_v_neigh_print
//Imprime la lista de vecinos de un unico salto.
//Realiza dos recorridos, el primero de las diferentes interfaces de un nodo
//el segundo por cada una de ellas los vecinos y para esto realiza un llamado
//por cada nodo a imprimir

//Las secuencias de llamado a batadv_v_hardif_neigh_print son las siguientes 
//batadv_v_neigh_print----->batadv_v_hardif_neigh_print
batadv_v_neigh_print
static void
batadv_v_hardif_neigh_print(struct seq_file *seq,
			    struct batadv_hardif_neigh_node *hardif_neigh)
{
	int last_secs, last_msecs;
	u32 throughput;

	//conversion de jiffies a secs
	last_secs = jiffies_to_msecs(jiffies - hardif_neigh->last_seen) / 1000;
	//resto de la conversion de jiffies a secs. Son los msecs
	last_msecs = jiffies_to_msecs(jiffies - hardif_neigh->last_seen) % 1000;
	throughput = ewma_throughput_read(&hardif_neigh->bat_v.throughput);

	//imprime direccion mac, ultimo visto en segundos y milisegundos, 
	//rendimiento / 10 con su resto y el nombre de la interfaz entrante
	seq_printf(seq, "%pM %4i.%03is (%9u.%1u) [%10s]\n",
		   hardif_neigh->addr, last_secs, last_msecs, throughput / 10,
		   throughput % 10, hardif_neigh->if_incoming->net_dev->name);
}

/**
 * batadv_v_neigh_print - print the single hop neighbour list
 * @bat_priv: the bat priv with all the soft interface information
 * @seq: neighbour table seq_file struct
 */

//Imprime la lista de vecinos de un unico salto.
//Realiza dos recorridos, el primero de las diferentes interfaces de un nodo
//el segundo por cada una de ellas los vecinos

//No es invocado por metodos
static void batadv_v_neigh_print(struct batadv_priv *bat_priv,
				 struct seq_file *seq)
{
	//declaracion de variables
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct batadv_hardif_neigh_node *hardif_neigh;
	struct batadv_hard_iface *hard_iface;
	int batman_count = 0;

	//Impresion cabecera de campos a imprimir
	seq_puts(seq,
		 "  Neighbor        last-seen ( throughput) [        IF]\n");

	//bloqueo para iniciar concurrencia
	rcu_read_lock();
	//macro que recorre la lista de interfaces concurrentemente
	list_for_each_entry_rcu(hard_iface, &batadv_hardif_list, list) {
		if (hard_iface->soft_iface != net_dev)
			continue;

		//macro que recorre la lista de vecinos concurrentemente
		hlist_for_each_entry_rcu(hardif_neigh,
					 &hard_iface->neigh_list, list) {
			//imprime un nodo vecino ELP.
			batadv_v_hardif_neigh_print(seq, hardif_neigh);
			batman_count++;
		}
	}
	rcu_read_unlock();

	//impresion de tabla vacia
	if (batman_count == 0)
		seq_puts(seq, "No batman nodes in range ...\n");
}
#endif

/**
 * batadv_v_neigh_dump_neigh - Dump a neighbour into a message
 * @msg: Netlink message to dump into
 * @portid: Port making netlink request
 * @seq: Sequence number of netlink message
 * @hardif_neigh: Neighbour to dump
 *
 * Return: Error code, or 0 on success
 */

//Crea un mensaje generico a partir de un nodo vecino
//El mensaje tiene un header, direccion mac, interfaz entrante,
//ultimo visto en milisegundos y rendimiento
//Si en el momento de crear aparece algun error se cancela y se devuelve el codigo de error

//Es invocada por:
//batman_v.c: batadv_v_neigh_dump_hardif
//Crea un mensaje generico a partir de un hard interface
//El metodo recorre la lista de vecinos concurrentemente y por cada uno de ellos 
//crea un mensaje llamando a batadv_v_neigh_dump_neigh

//Las secuencias de llamado a batadv_v_neigh_dump_neigh son las siguientes 
//batadv_v_neigh_dump_hardif----->batadv_v_neigh_dump_neigh

static int
batadv_v_neigh_dump_neigh(struct sk_buff *msg, u32 portid, u32 seq,
			  struct batadv_hardif_neigh_node *hardif_neigh)
{
	void *hdr;
	unsigned int last_seen_msecs;
	u32 throughput;

	//conversion de jiffies a milisegundos
	last_seen_msecs = jiffies_to_msecs(jiffies - hardif_neigh->last_seen);
	throughput = ewma_throughput_read(&hardif_neigh->bat_v.throughput);
	throughput = throughput * 100;

	//Agrega un encabezado generico
	hdr = genlmsg_put(msg, portid, seq, &batadv_netlink_family, NLM_F_MULTI,
			  BATADV_CMD_GET_NEIGHBORS);
	//deteccion de error. Si hay error devuelve -ENOBUFS
	if (!hdr)
		return -ENOBUFS;

	//Agrega un atributo al buffer socket(nla_put)
	//Agrega un atributo u32(hardif_neigh->if_incoming->net_dev->ifindex) al buffer socket
	//Agrega un atributo u32(last_seen_msecs) al buffer socket
	//Agrega un atributo u32(throughtput) al buffer socket
	if (nla_put(msg, BATADV_ATTR_NEIGH_ADDRESS, ETH_ALEN,
		    hardif_neigh->addr) ||
	    nla_put_u32(msg, BATADV_ATTR_HARD_IFINDEX,
			hardif_neigh->if_incoming->net_dev->ifindex) ||
	    nla_put_u32(msg, BATADV_ATTR_LAST_SEEN_MSECS,
			last_seen_msecs) ||
	    nla_put_u32(msg, BATADV_ATTR_THROUGHPUT, throughput))
	    //Si aparece error en alguno de ellos se redirige a nla_put_failure
		goto nla_put_failure;

	//Finaliza un mensaje generico netlink
	genlmsg_end(msg, hdr);
	return 0;

 nla_put_failure:
 	//si falla cancela y devuelve codigo de error
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

/**
 * batadv_v_neigh_dump_hardif - Dump the  neighbours of a hard interface  into
 *  a message
 * @msg: Netlink message to dump into
 * @portid: Port making netlink request
 * @seq: Sequence number of netlink message
 * @bat_priv: The bat priv with all the soft interface information
 * @hard_iface: The hard interface to be dumped
 * @idx_s: Entries to be skipped
 *
 * This function assumes the caller holds rcu_read_lock().
 *
 * Return: Error code, or 0 on success
 */
//Crea un mensaje generico a partir de un hard interface
//El metodo recorre la lista de vecinos concurrentemente y por cada uno de ellos 
//crea un mensaje llamando a batadv_v_neigh_dump_neigh
//Devuelve cero o el codigo de error

//Es invocada por:
//batman_v.c: batadv_v_neigh_dump
//Convierte los vecinos de una hard interface en un mensaje.
//Para eso usa batadv_v_neigh_dump_hardif que crea un mensaje de un hard iterface
//pasada por parametro

//Las secuencias de llamado a batadv_v_neigh_dump_hardif son las siguientes 
//batadv_v_neigh_dump----->batadv_v_neigh_dump_hardif

static int
batadv_v_neigh_dump_hardif(struct sk_buff *msg, u32 portid, u32 seq,
			   struct batadv_priv *bat_priv,
			   struct batadv_hard_iface *hard_iface,
			   int *idx_s)
{
	struct batadv_hardif_neigh_node *hardif_neigh;
	int idx = 0;

	//recorre la lista de vecinos
	hlist_for_each_entry_rcu(hardif_neigh,
				 &hard_iface->neigh_list, list) {
		if (idx++ < *idx_s)
			continue;

		//Crea los mensajes a partir de un vecino
		if (batadv_v_neigh_dump_neigh(msg, portid, seq, hardif_neigh)) {
			*idx_s = idx - 1;
			return -EMSGSIZE;
		}
	}

	*idx_s = 0;
	return 0;
}

/**
 * batadv_v_neigh_dump - Dump the neighbours of a hard interface  into a
 *  message
 * @msg: Netlink message to dump into
 * @cb: Control block containing additional options
 * @bat_priv: The bat priv with all the soft interface information
 * @single_hardif: Limit dumping to this hard interface
 */
//Convierte los vecinos de una hard interface en un mensaje.
//Para eso usa batadv_v_neigh_dump_hardif que crea un mensaje de un hard iterface
//pasada por parametro

//No es invocado por metodos
static void
batadv_v_neigh_dump(struct sk_buff *msg, struct netlink_callback *cb,
		    struct batadv_priv *bat_priv,
		    struct batadv_hard_iface *single_hardif)
{
	struct batadv_hard_iface *hard_iface;
	int i_hardif = 0;
	int i_hardif_s = cb->args[0];
	int idx = cb->args[1];
	int portid = NETLINK_CB(cb->skb).portid;

	//bloqueo para ejecutar concurrentemente
	rcu_read_lock();
	if (single_hardif) {
		if (i_hardif_s == 0) {
			//Crea un mensaje generico a partir de un hard interface
			//El metodo recorre la lista de vecinos concurrentemente y por cada uno de ellos 
			//crea un mensaje llamando a batadv_v_neigh_dump_neigh
			if (batadv_v_neigh_dump_hardif(msg, portid,
						       cb->nlh->nlmsg_seq,
						       bat_priv, single_hardif,
						       &idx) == 0)
				//si se creo el mensaje aumenta el contador en 1
				i_hardif++;
		}
	} else {
		//se obtiene la lista de hardif
		list_for_each_entry_rcu(hard_iface, &batadv_hardif_list, list) {
			//Chequea que la interfaz a crear el mensaje sea la pasada por parametro
			if (hard_iface->soft_iface != bat_priv->soft_iface)
				continue;

			if (i_hardif++ < i_hardif_s)
				continue;

			//Crea un mensaje generico a partir de un hard interface
			//El metodo recorre la lista de vecinos concurrentemente y por cada uno de ellos 
			//crea un mensaje llamando a batadv_v_neigh_dump_neigh
			if (batadv_v_neigh_dump_hardif(msg, portid,
						       cb->nlh->nlmsg_seq,
						       bat_priv, hard_iface,
						       &idx)) {
				i_hardif--;
				break;
			}
		}
	}
	//fin de concurrencia
	rcu_read_unlock();

	cb->args[0] = i_hardif;
	cb->args[1] = idx;
}

#ifdef CONFIG_BATMAN_ADV_DEBUGFS
/**
 * batadv_v_orig_print - print the originator table
 * @bat_priv: the bat priv with all the soft interface information
 * @seq: debugfs table seq_file struct
 * @if_outgoing: the outgoing interface for which this should be printed
 */

//Este metodo imprime la "originator table"
//Recorre concurrentemente la hash del nodo origen . Por cada vecino 
//imprime nodo origen, ultimo visto en segundos y milisegundos, 
//rendimiento / 10 con su resto, direccion mac del vecino
// y el nombre de la interfaz entrante

//No es invocado por ningun metodo
static void batadv_v_orig_print(struct batadv_priv *bat_priv,
				struct seq_file *seq,
				struct batadv_hard_iface *if_outgoing)
{
	struct batadv_neigh_node *neigh_node;
	struct batadv_hashtable *hash = bat_priv->orig_hash;
	int last_seen_msecs, last_seen_secs;
	struct batadv_orig_node *orig_node;
	struct batadv_neigh_ifinfo *n_ifinfo;
	unsigned long last_seen_jiffies;
	struct hlist_head *head;
	int batman_count = 0;
	u32 i;

	//Impresion de campos de la tabla
	seq_puts(seq,
		 "  Originator      last-seen ( throughput)           Nexthop [outgoingIF]:   Potential nexthops ...\n");

	//Recorrido de la hash donde se guardan
	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];

		//Bloqueo para evitar inconsistencias en concurrencia
		rcu_read_lock();
		//Por cada vecino de orig_node
		hlist_for_each_entry_rcu(orig_node, head, hash_entry) {
			//Obtiene un nodo vecino de orig_node
			neigh_node = batadv_orig_router_get(orig_node,
							    if_outgoing);
			if (!neigh_node)
				continue;
			//informacion de la if_info del neigh_node
			n_ifinfo = batadv_neigh_ifinfo_get(neigh_node,
							   if_outgoing);
			if (!n_ifinfo)
				goto next;

			//Obtiene la ultima vez en jiffies
			last_seen_jiffies = jiffies - orig_node->last_seen;
			//Conversion de jiffies a milisegundos
			last_seen_msecs = jiffies_to_msecs(last_seen_jiffies);
			//Conversion a segundos y milisegundos
			last_seen_secs = last_seen_msecs / 1000;
			last_seen_msecs = last_seen_msecs % 1000;

			//Imprime una fila de la tabla.
			//imprime nodo origen, ultimo visto en segundos y milisegundos, 
			//rendimiento / 10 con su resto, direccion mac del vecino
			// y el nombre de la interfaz entrante
			seq_printf(seq, "%pM %4i.%03is (%9u.%1u) %pM [%10s]:",
				   orig_node->orig, last_seen_secs,
				   last_seen_msecs,
				   n_ifinfo->bat_v.throughput / 10,
				   n_ifinfo->bat_v.throughput % 10,
				   neigh_node->addr,
				   neigh_node->if_incoming->net_dev->name);

			//Imprime la "originator table" del nodo orig_node pasado por parametro
			batadv_v_orig_print_neigh(orig_node, if_outgoing, seq);
			seq_puts(seq, "\n");
			//Contador de filas de la tabla(usado para imprimir o no el mensaje de vacio)
			batman_count++;

next:
			//reduce el refcounter de neigh_node y posiblemente la libera
			batadv_neigh_node_put(neigh_node);
			if (n_ifinfo)
				//reduce el refcounter de n_ifinfo y posiblemente la libera
				batadv_neigh_ifinfo_put(n_ifinfo);
		}
		//Fin de concurrencia.
		rcu_read_unlock();
	}
	//Impresion de tabla vacia
	if (batman_count == 0)
		seq_puts(seq, "No batman nodes in range ...\n");
}
#endif

/**
 * batadv_v_orig_dump_subentry - Dump an originator subentry into a
 *  message
 * @msg: Netlink message to dump into
 * @portid: Port making netlink request
 * @seq: Sequence number of netlink message
 * @bat_priv: The bat priv with all the soft interface information
 * @if_outgoing: Limit dump to entries with this outgoing interface
 * @orig_node: Originator to dump
 * @neigh_node: Single hops neighbour
 * @best: Is the best originator
 *
 * Return: Error code, or 0 on success
 */

//Convierte una subentrada de un orig en un mensaje.
//Para eso usa informacion de la interfaz como rendimienot y last_seen
//Si la interfaz saliente es default o es la misma que la entrante
//termina la ejecucion de la funcion retornando cero y no crea el mensaje
//Devuelve 0 si no hay errores o el numero (negativo) de error


//Es invocada por:
//batman_v.c: batadv_v_orig_dump_entry
//Convierte una entrada de un orig en un mensaje.
//Recorre la lista de vecinos y por cada uno de ellos crea un mensaje 
//llamando al metodo batadv_v_orig_dump_subentry

//Las secuencias de llamado a batadv_v_orig_dump_subentry son las siguientes 
//batadv_v_orig_dump_entry----->batadv_v_orig_dump_subentry

static int
batadv_v_orig_dump_subentry(struct sk_buff *msg, u32 portid, u32 seq,
			    struct batadv_priv *bat_priv,
			    struct batadv_hard_iface *if_outgoing,
			    struct batadv_orig_node *orig_node,
			    struct batadv_neigh_node *neigh_node,
			    bool best)
{
	struct batadv_neigh_ifinfo *n_ifinfo;
	unsigned int last_seen_msecs;
	u32 throughput;
	void *hdr;

	//informacion de la if_info del neigh_node
	n_ifinfo = batadv_neigh_ifinfo_get(neigh_node, if_outgoing);
	if (!n_ifinfo)
		return 0;

	//Obtiene el rendimiento del enlace
	throughput = n_ifinfo->bat_v.throughput * 100;

	//reduce el refcounter de n_ifinfo y posiblemente la libera
	batadv_neigh_ifinfo_put(n_ifinfo);

	//Obtiene el visto en formato de segundos. Conversion de jiffies a msecs
	last_seen_msecs = jiffies_to_msecs(jiffies - orig_node->last_seen);

	//Si la interfaz saliente es default o es la misma que la entrante
	//termina la ejecucion de la funcion retornando cero
	if (if_outgoing != BATADV_IF_DEFAULT &&
	    if_outgoing != neigh_node->if_incoming)
		return 0;

	//si llega aca es porque la interfaz saliente no es default y no es la 
	//misma que la entrante

	//Agrega un encabezado generico
	hdr = genlmsg_put(msg, portid, seq, &batadv_netlink_family, NLM_F_MULTI,
			  BATADV_CMD_GET_ORIGINATORS);
	//Chequea que no haya error al crear el encabezado
	if (!hdr)
		return -ENOBUFS;

	//Agrega un atributo al buffer socket(orig_node->orig)
	//Agrega un atributo al buffer socket(neigh_node->addr)
	//Agrega un atributo u32(hardif_neigh->if_incoming->net_dev->ifindex) al buffer socket
	//Agrega un atributo u32(throughtput) al buffer socket
	//Agrega un atributo u32(last_seen_msecs) al buffer socket
	if (nla_put(msg, BATADV_ATTR_ORIG_ADDRESS, ETH_ALEN, orig_node->orig) ||
	    nla_put(msg, BATADV_ATTR_NEIGH_ADDRESS, ETH_ALEN,
		    neigh_node->addr) ||
	    nla_put_u32(msg, BATADV_ATTR_HARD_IFINDEX,
			neigh_node->if_incoming->net_dev->ifindex) ||
	    nla_put_u32(msg, BATADV_ATTR_THROUGHPUT, throughput) ||
	    nla_put_u32(msg, BATADV_ATTR_LAST_SEEN_MSECS,
			last_seen_msecs))
		//se redirige a nla_put_failure si hay algun error
		goto nla_put_failure;

	if (best && nla_put_flag(msg, BATADV_ATTR_FLAG_BEST))
		goto nla_put_failure;

	//Finaliza un mensaje generico netlink
	genlmsg_end(msg, hdr);
	return 0;

 nla_put_failure:
  	//si falla cancela y devuelve codigo de error
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

/**
 * batadv_v_orig_dump_entry - Dump an originator entry into a message
 * @msg: Netlink message to dump into
 * @portid: Port making netlink request
 * @seq: Sequence number of netlink message
 * @bat_priv: The bat priv with all the soft interface information
 * @if_outgoing: Limit dump to entries with this outgoing interface
 * @orig_node: Originator to dump
 * @sub_s: Number of sub entries to skip
 *
 * This function assumes the caller holds rcu_read_lock().
 *
 * Return: Error code, or 0 on success
 */

//Convierte una entrada de un orig en un mensaje.
//Recorre la lista de vecinos y por cada uno de ellos crea un mensaje 
//llamando al metodo batadv_v_orig_dump_subentry
//Hace una distincion entre el mejor de los vecinos y el resto
//Devuelve 0 si no hay errores o el numero (negativo) de error

//Es invocada por:
//batman_v.c: batadv_v_orig_dump_bucket
//Convierte una originator bucket en mensaje
//Recorre la hash pasada por parametro y crea un mensaje de cada orig_node
//usando el metodo batadv_v_orig_dump_entry


//Las secuencias de llamado a batadv_v_orig_dump_entry son las siguientes 
//batadv_v_orig_dump_bucket----->batadv_v_orig_dump_entry
static int
batadv_v_orig_dump_entry(struct sk_buff *msg, u32 portid, u32 seq,
			 struct batadv_priv *bat_priv,
			 struct batadv_hard_iface *if_outgoing,
			 struct batadv_orig_node *orig_node, int *sub_s)
{
	struct batadv_neigh_node *neigh_node_best;
	struct batadv_neigh_node *neigh_node;
	int sub = 0;
	bool best;

	//obtiene el mejor vecino de la interfaz saliente(if_outgoing)
	neigh_node_best = batadv_orig_router_get(orig_node, if_outgoing);
	if (!neigh_node_best)
		goto out;

	//recorre la lista de vecinos de nodo origen pasado por parametro
	hlist_for_each_entry_rcu(neigh_node, &orig_node->neigh_list, list) {
		if (sub++ < *sub_s)
			continue;

		//marca como true si el nodo a crear la subentrada es el mejor
		best = (neigh_node == neigh_node_best);


		//Convierte una subentrada de un orig en un mensaje.
		if (batadv_v_orig_dump_subentry(msg, portid, seq, bat_priv,
						if_outgoing, orig_node,
						neigh_node, best)) {
			//reduce el refcounter de neigh_node_best y posiblemente la libera
			batadv_neigh_node_put(neigh_node_best);

			*sub_s = sub - 1;
			return -EMSGSIZE;
		}
	}

 out:
	if (neigh_node_best)
		//reduce el refcounter de neigh_node_best y posiblemente la libera
		batadv_neigh_node_put(neigh_node_best);

	*sub_s = 0;
	return 0;
}

/**
 * batadv_v_orig_dump_bucket - Dump an originator bucket into a
 *  message
 * @msg: Netlink message to dump into
 * @portid: Port making netlink request
 * @seq: Sequence number of netlink message
 * @bat_priv: The bat priv with all the soft interface information
 * @if_outgoing: Limit dump to entries with this outgoing interface
 * @head: Bucket to be dumped
 * @idx_s: Number of entries to be skipped
 * @sub: Number of sub entries to be skipped
 *
 * Return: Error code, or 0 on success
 */

//Convierte una originator bucket en mensaje
//Recorre la hash pasada por parametro y crea un mensaje de cada orig_node
//usando el metodo batadv_v_orig_dump_entry
//Devuelve 0 si no hay errores o el numero (negativo) de error

//Es invocada por:
//batman_v.c: batadv_v_orig_dump_bucket
//obtiene la hash de los originators. Recorre la hash y por cada entrada 
//llama al metodo batadv_v_orig_dump_bucket para crear un mensaje

//Las secuencias de llamado a batadv_v_orig_dump_bucket son las siguientes 
//batadv_v_orig_dump----->batadv_v_orig_dump_bucket

static int
batadv_v_orig_dump_bucket(struct sk_buff *msg, u32 portid, u32 seq,
			  struct batadv_priv *bat_priv,
			  struct batadv_hard_iface *if_outgoing,
			  struct hlist_head *head, int *idx_s, int *sub)
{
	struct batadv_orig_node *orig_node;
	int idx = 0;

	//Bloqueo para evitar inconsistencias en concurrencia
	rcu_read_lock();
	//Por cada entrada de la hash pasada por parametro crea un mensaje
	hlist_for_each_entry_rcu(orig_node, head, hash_entry) {
		if (idx++ < *idx_s)
			continue;

		//Convierte la tabla en un mensaje.
		if (batadv_v_orig_dump_entry(msg, portid, seq, bat_priv,
					     if_outgoing, orig_node, sub)) {
			//Fin de concurrencia.
			rcu_read_unlock();
			*idx_s = idx - 1;
			//Retorna numero de error
			return -EMSGSIZE;
		}
	}
	//Fin de concurrencia.
	rcu_read_unlock();

	*idx_s = 0;
	*sub = 0;
	return 0;
}

/**
 * batadv_v_orig_dump - Dump the originators into a message
 * @msg: Netlink message to dump into
 * @cb: Control block containing additional options
 * @bat_priv: The bat priv with all the soft interface information
 * @if_outgoing: Limit dump to entries with this outgoing interface
 */

//obtiene la hash de los originators. Recorre la hash y por cada entrada 
//llama al metodo batadv_v_orig_dump_bucket para crear un mensaje

//No es invocada por ningun metodo
static void
batadv_v_orig_dump(struct sk_buff *msg, struct netlink_callback *cb,
		   struct batadv_priv *bat_priv,
		   struct batadv_hard_iface *if_outgoing)
{
	//obtiene la has de los originators
	struct batadv_hashtable *hash = bat_priv->orig_hash;
	struct hlist_head *head;
	int bucket = cb->args[0];
	int idx = cb->args[1];
	int sub = cb->args[2];
	int portid = NETLINK_CB(cb->skb).portid;

	//recorrido de la hash
	while (bucket < hash->size) {
		head = &hash->table[bucket];

		//Convierte una originator bucket en mensaje
		if (batadv_v_orig_dump_bucket(msg, portid,
					      cb->nlh->nlmsg_seq,
					      bat_priv, if_outgoing, head, &idx,
					      &sub))
			break;

		bucket++;
	}

	cb->args[0] = bucket;
	cb->args[1] = idx;
	cb->args[2] = sub;
}

//Obtengo las diferencias de rendimiento entre los nodos vecinos
//Es invocado en la inicializacion del "struct static struct batadv_algo_ops batadv_batman_v __read_mostly".
//
//Secuencia de de llamadas:
//			-bat_v. --> __read_mostly --> batadv_v_neigh_cmp
//No es invocada en ningun metodo
static int batadv_v_neigh_cmp(struct batadv_neigh_node *neigh1,
			      struct batadv_hard_iface *if_outgoing1,
			      struct batadv_neigh_node *neigh2,
			      struct batadv_hard_iface *if_outgoing2)
{
	struct batadv_neigh_ifinfo *ifinfo1, *ifinfo2;
	int ret = 0;
	
	//busca la ifinfo del primer nodo vecino pasado como parametro
	ifinfo1 = batadv_neigh_ifinfo_get(neigh1, if_outgoing1);
	// si falla el primero, retorno 0
	if (WARN_ON(!ifinfo1))
		goto err_ifinfo1;
	//busca la ifinfo del segundo nodo vecino pasado como parametro
	ifinfo2 = batadv_neigh_ifinfo_get(neigh2, if_outgoing2);
	
	//si tengo error, libero de memoria ifinfo1
	if (WARN_ON(!ifinfo2))
		goto err_ifinfo2;

	//obtengo la diferencia de rendimientos entre los nodos vecinos
	ret = ifinfo1->bat_v.throughput - ifinfo2->bat_v.throughput;
	
	//libera la informacion de ifinfo2
	batadv_neigh_ifinfo_put(ifinfo2);
err_ifinfo2:
	batadv_neigh_ifinfo_put(ifinfo1);
err_ifinfo1:
	return ret;
}


//Compara que el throughput de un nodo con otro, verificando que el throughput de uno supero los 3/4 del throughput del otro nodo.
//En caso de cualquier error en las invocaciones retorna falso.
//
//No es invocado. Se utiliza en la inicializacion de la estructura de bat_v
static bool batadv_v_neigh_is_sob(struct batadv_neigh_node *neigh1,
				  struct batadv_hard_iface *if_outgoing1,
				  struct batadv_neigh_node *neigh2,
				  struct batadv_hard_iface *if_outgoing2)
{
	//Declaracion de variables de estado
	struct batadv_neigh_ifinfo *ifinfo1, *ifinfo2;
	u32 threshold;
	bool ret = false;
	//busca la ifinfo del primer nodo vecino pasado como parametro
	ifinfo1 = batadv_neigh_ifinfo_get(neigh1, if_outgoing1);
	if (WARN_ON(!ifinfo1))
		//retorno falso
		goto err_ifinfo1;
	//busca la ifinfo del segundo nodo vecino pasado como parametro
	ifinfo2 = batadv_neigh_ifinfo_get(neigh2, if_outgoing2);
	if (WARN_ON(!ifinfo2))
		goto err_ifinfo2;

	
	threshold = ifinfo1->bat_v.throughput / 4;
	//Actualizo el limite con 3/4 del rendimiento actual
	threshold = ifinfo1->bat_v.throughput - threshold;

	//verifico que el throughput hacia el nodo 2 supere al limite (3/4 throughput de ir por la interfaz 1)
	ret = ifinfo2->bat_v.throughput > threshold;
	
	//libero la memoria de ocupada por ifinfo2
	batadv_neigh_ifinfo_put(ifinfo2);
err_ifinfo2:
	//libero la memoria de ocupada por ifinfo1
	batadv_neigh_ifinfo_put(ifinfo1);
err_ifinfo1:
	return ret;
}

/**
 * batadv_v_init_sel_class - initialize GW selection class
 * @bat_priv: the bat priv with all the soft interface information
 */
//inicializacion de la clase de seleccion del gateway
static void batadv_v_init_sel_class(struct batadv_priv *bat_priv)
{
	/* set default throughput difference threshold to 5Mbps */
	/* establece un limite de diferencia de rendimiento predeterminado en 5Mbps */
	atomic_set(&bat_priv->gw.sel_class, 50);
}


// Esta funcion es seteada como parte de la inicilizacion del struct: "static struct batadv_algo_ops batadv_batman_v __read_mostly".
// La propiedad setea es gw.store_sel_class
// 
//No es invocada en ningun metodo.
static ssize_t batadv_v_store_sel_class(struct batadv_priv *bat_priv,
					char *buff, size_t count)
{
	u32 old_class, class;
	
	//retorna el rendimiento de la interfaz, en caso de error notifico el mismo . El valor es devuelto en la variable "class".
	if (!batadv_parse_throughput(bat_priv->soft_iface, buff,
				     "B.A.T.M.A.N. V GW selection class",
				     &class))
		return -EINVAL; //flag de argumento invalido

	//antes de actualizar la vieja sel_class (throughput del gateway), obtengo su referencia
	old_class = atomic_read(&bat_priv->gw.sel_class);
	//actualizo la sel_class con la obtenida anteriormente
	atomic_set(&bat_priv->gw.sel_class, class);
	
	//si son distintos los rendimientos obtenidos
	if (old_class != class)
		// Si son distintos, se fuerza una reseleccion de gateway. Se un indicador para recordar al
		// componente GW que realice una nueva reselección del gateway.Sin embargo, esta función no 
		// garantiza que el gateway actual va a ser deseleccionado. El mecanismo de reselección puede 
		// elegir el mismo gateway una vez más.
		batadv_gw_reselect(bat_priv);
	return count;
}


//Imprime la informacion del gateway en Mbs (throughput actualizado en "batadv_v_store_sel_class")
//No es invocado en ningun metodo. (solo en inicializacion del struct)
static ssize_t batadv_v_show_sel_class(struct batadv_priv *bat_priv, char *buff)
{
	u32 class = atomic_read(&bat_priv->gw.sel_class);

	return sprintf(buff, "%u.%u MBit\n", class / 10, class % 10);
}

/**
 * batadv_v_gw_throughput_get - retrieve the GW-bandwidth for a given GW
 * @gw_node: the GW to retrieve the metric for
 * @bw: the pointer where the metric will be stored. The metric is computed as
 *  the minimum between the GW advertised throughput and the path throughput to
 *  it in the mesh
 *
 * Return: 0 on success, -1 on failure
 */
//La funcion "batadv_v_gw_throughput_get" devuelve en la variable 'bw' el ancho de banda GW para un determinado gateway.
// La métrica se calcula como el mínimo entre el throughput del GW y el rendimiento del trayecto en la red.
//
//Es invocada en: 
//		-bat_v.c -->batadv_v_gw_get_best_gw_node -->batadv_v_gw_throughput_get. 
//			    Se utiliza al buscar al mejor gateway con la mejor metrica.
//		-bat_v.c -->batadv_v_gw_is_eligible -->batadv_v_gw_throughput_get.
//			    Se utiliza para verificar si un originator puede ser seleccionado como gateway (GW).
//
//Retorna 0 si tiene exito, o -1 en caso de error.
static int batadv_v_gw_throughput_get(struct batadv_gw_node *gw_node, u32 *bw)
{
	//Declaracion de variables utilizadas en el metodo
	struct batadv_neigh_ifinfo *router_ifinfo = NULL;
	struct batadv_orig_node *orig_node;
	struct batadv_neigh_node *router;
	int ret = -1;
	
	//Obtengo la estructura del nodo originator correspondiente (puntero)
	orig_node = gw_node->orig_node;
	//obtengo el nodo vecino ("per outgoing") que deberia ser enrutador del nodo originator 
	//El metodo 'batadv_orig_router_get'  devuelve el enrutador a partir de un listado de
	//estos contenidos en la estructura del origninator.
	router = batadv_orig_router_get(orig_node, BATADV_IF_DEFAULT);
	if (!router)
		goto out;
	
	//obtengo la informacion del nodo vecino("per outgoing").
	router_ifinfo = batadv_neigh_ifinfo_get(router, BATADV_IF_DEFAULT);
	if (!router_ifinfo)
		goto out;

	/* the GW metric is computed as the minimum between the path throughput
	 * to reach the GW itself and the advertised bandwidth.
	 * This gives us an approximation of the effective throughput that the
	 * client can expect via this particular GW node
	 */
	/* la métrica de GW se calcula como el mínimo entre el rendimiento de la ruta
	* para llegar al propio GW y al ancho de banda anunciado.
	* Esto nos da una aproximación del rendimiento efectivo que el
	* el cliente puede esperar a través de este nodo GW en particular
	*/
	*bw = router_ifinfo->bat_v.throughput;
	*bw = min_t(u32, *bw, gw_node->bandwidth_down);

	ret = 0;
out:
	//Libero los recursos utilizados
	if (router)
		batadv_neigh_node_put(router);
	if (router_ifinfo)
		batadv_neigh_ifinfo_put(router_ifinfo);

	return ret;
}

/**
 * batadv_v_gw_get_best_gw_node - retrieve the best GW node
 * @bat_priv: the bat priv with all the soft interface information
 *
 * Return: the GW node having the best GW-metric, NULL if no GW is known
 */
//La funcion retorna el mejor nodo gateway (GW).
//Returna el nodo con la mejor metrica GW, o NULL, si no se conoce el GW.
//
//No es invocada en ningun metodo, solo se setea en la struct de configuracion de bat_v.
static struct batadv_gw_node *
batadv_v_gw_get_best_gw_node(struct batadv_priv *bat_priv)
{
	//Declaracion de variables del metodo
	struct batadv_gw_node *gw_node, *curr_gw = NULL;
	u32 max_bw = 0, bw;

	//Bloqueo los recursos para no tener inconsistencias
	rcu_read_lock();
	//recorre el listado de GWs disponibles de la interfaz que recibe como parametro (enrutadores).
	hlist_for_each_entry_rcu(gw_node, &bat_priv->gw.gateway_list, list) {
		//Si no posee referencias continuo con el siguiente GW
		if (!kref_get_unless_zero(&gw_node->refcount))
			continue;
		//Obtengo el throughput del nodo, devuelto en la variable "bw". Si ocurre algun error (return -1), libero el recurso "gw_node"
		if (batadv_v_gw_throughput_get(gw_node, &bw) < 0)
			goto next;
		//Si el throughput de nodo seleccionado no supera el rendimiento del nodo seleccionado hasta el momento, libero el recurso "gw_node"
		if (curr_gw && (bw <= max_bw))
			goto next;
		
		//Si es distindo de null
		if (curr_gw)
			//libero la memoria de la variable "curr_gw"
			batadv_gw_node_put(curr_gw);
		//Si llego hasta esta instancia, es porque se encontro un mejor candidato
		curr_gw = gw_node;
		kref_get(&curr_gw->refcount);
		//Seteo el mejor throughput obtenido hasta el momento
		max_bw = bw;

next:
		batadv_gw_node_put(gw_node);
	}
	rcu_read_unlock();
	//Libero el bloqueo
	return curr_gw;
}

/**
 * batadv_v_gw_is_eligible - check if a originator would be selected as GW
 * @bat_priv: the bat priv with all the soft interface information
 * @curr_gw_orig: originator representing the currently selected GW
 * @orig_node: the originator representing the new candidate
 *
 * Return: true if orig_node can be selected as current GW, false otherwise
 */
//La funcion "batadv_v_gw_is_eligible" verifica si el originator deberia ser seleccionado como GW.
//
//Retorna "true" si el orignator actual puede ser seleccionado como GW, o "false" en caso contrario.
//
//No es invocada en ningun metodo, solo se setea en la struct de configuracion de bat_v.
static bool batadv_v_gw_is_eligible(struct batadv_priv *bat_priv,
				    struct batadv_orig_node *curr_gw_orig,
				    struct batadv_orig_node *orig_node)
{
	//Declaracion de variables del metodo.
	struct batadv_gw_node *curr_gw, *orig_gw = NULL;
	u32 gw_throughput, orig_throughput, threshold;
	bool ret = false;
	
	//Obtengo el limite de la interfaz
	threshold = atomic_read(&bat_priv->gw.sel_class);
	
	//Solicito el originator utilizado como GW actual
	curr_gw = batadv_gw_node_get(bat_priv, curr_gw_orig);
	//Si no lo encuentro por algun error
	if (!curr_gw) {
		ret = true;
		//Libero los recursos utilizados y retorno true.
		goto out;
	}

	//Obtengo el rendimiento del mismo, asigna i ocurre algun error returno true
	if (batadv_v_gw_throughput_get(curr_gw, &gw_throughput) < 0) {
		ret = true;
		goto out;
	}
	
	//Obtengo los mismos datos con el originator
	orig_gw = batadv_gw_node_get(bat_priv, orig_node);
	if (!orig_node)
		goto out;

	if (batadv_v_gw_throughput_get(orig_gw, &orig_throughput) < 0)
		goto out;

	//Si el originator obtenido posee menor rendimiento que el actual, libero recursos y retorno.
	if (orig_throughput < gw_throughput)
		goto out;

	//Si tampoco sepera el limite, libero recursos y retorno.
	if ((orig_throughput - gw_throughput) < threshold)
		goto out;
	
	//Logging--> imprimo la info del mejor gateway encontrado.
	batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
		   "Restarting gateway selection: better gateway found (throughput curr: %u, throughput new: %u)\n",
		   gw_throughput, orig_throughput);

	ret = true;
out:
	if (curr_gw)
		batadv_gw_node_put(curr_gw);
	if (orig_gw)
		batadv_gw_node_put(orig_gw);

	return ret;
}

#ifdef CONFIG_BATMAN_ADV_DEBUGFS
/**********************************************IMPRESIONES DE DEBUGGING**********************************************/

/* fails if orig_node has no router */
//La funcion "batadv_v_gw_write_buffer_text" imprime la siguiente informacion del gateway:
//		-originator ethernet address
//		-last throughput metric received from originator via this neigh / 10
//		-last throughput metric received from originator via this neigh%10 + la direccion del router (GW)
//		-nombre de la interfaz fisica saliente
//		-ancho de banda de descarga del GW /10
//		-ancho de banda de descarga del GW % 10
//		-ancho de banda de subida del GW / 10
//		-ancho de banda de subida del GW % 10
//
//Es invocada en: 
//		bat_v.c --> batadv_v_gw_print --> batadv_v_gw_write_buffer_text
//			    Es llamada al hora de imprimir el listado de gateway de la interfaz fisica
static int batadv_v_gw_write_buffer_text(struct batadv_priv *bat_priv,
					 struct seq_file *seq,
					 const struct batadv_gw_node *gw_node)
{
	struct batadv_gw_node *curr_gw;
	struct batadv_neigh_node *router;
	struct batadv_neigh_ifinfo *router_ifinfo = NULL;
	int ret = -1;

	router = batadv_orig_router_get(gw_node->orig_node, BATADV_IF_DEFAULT);
	//Si no posee router, libero recursos y retorno.
	if (!router)
		goto out;
	
	router_ifinfo = batadv_neigh_ifinfo_get(router, BATADV_IF_DEFAULT);
	//Si no posee datos/info, libero recursos y retorno.
	if (!router_ifinfo)
		goto out;

	//obtengo el GW seleccionado de la interfaz correspondiente
	curr_gw = batadv_gw_get_selected_gw_node(bat_priv);

	seq_printf(seq, "%s %pM (%9u.%1u) %pM [%10s]: %u.%u/%u.%u MBit\n",
		   (curr_gw == gw_node ? "=>" : "  "),
		   gw_node->orig_node->orig,
		   router_ifinfo->bat_v.throughput / 10,
		   router_ifinfo->bat_v.throughput % 10, router->addr,
		   router->if_incoming->net_dev->name,
		   gw_node->bandwidth_down / 10,
		   gw_node->bandwidth_down % 10,
		   gw_node->bandwidth_up / 10,
		   gw_node->bandwidth_up % 10);
	ret = seq_has_overflowed(seq) ? -1 : 0;

	//Libero los recursos utilizados
	if (curr_gw)
		batadv_gw_node_put(curr_gw);
out:
	if (router_ifinfo)
		batadv_neigh_ifinfo_put(router_ifinfo);
	if (router)
		batadv_neigh_node_put(router);
	return ret;
}

/**
 * batadv_v_gw_print - print the gateway list
 * @bat_priv: the bat priv with all the soft interface information
 * @seq: gateway table seq_file struct
 */
// La funcion "batadv_v_gw_print" imprime el listado de gateway de la interfaz pasada como parametro.
//
// No es invocada en ningun metodo, solo se setea en la struct de configuracion de bat_v.
static void batadv_v_gw_print(struct batadv_priv *bat_priv,
			      struct seq_file *seq)
{
	//Declaracion de variables de metodo
	struct batadv_gw_node *gw_node;
	int gw_count = 0;

	seq_puts(seq,
		 "      Gateway        ( throughput)           Nexthop [outgoingIF]: advertised uplink bandwidth\n");

	//Bloque el recurso para no generar inconsistencias
	rcu_read_lock();
	//Por cada nodo perteneciente al lista gateways de la interfaz, imprimo su informacion interna
	hlist_for_each_entry_rcu(gw_node, &bat_priv->gw.gateway_list, list) {
		/* fails if orig_node has no router */
		//Si se prudice algun error, salteo el nodo y continuo con el siguiente
		if (batadv_v_gw_write_buffer_text(bat_priv, seq, gw_node) < 0)
			continue;

		gw_count++;
	}
	rcu_read_unlock();
	//libero los recursos
	//Si la conteo es cero, no posee nodos GW a mi alrededor
	if (gw_count == 0)
		seq_puts(seq, "No gateways in range ...\n");
}
#endif

/**
 * batadv_v_gw_dump_entry - Dump a gateway into a message
 * @msg: Netlink message to dump into
 * @portid: Port making netlink request
 * @seq: Sequence number of netlink message
 * @bat_priv: The bat priv with all the soft interface information
 * @gw_node: Gateway to be dumped
 *
 * Return: Error code, or 0 on success
 */
//La funcion "batadv_v_gw_dump_entry" convierte la entrada de un gw en un mensaje.
//
//Es invocada en:
//		-bat_v.c --> batadv_v_gw_dump -->batadv_v_gw_dump_entry
//		Recorre la lista de nodos gw y por cada uno de ellos crea un mensaje 
//		llamando al metodo batadv_v_gw_dump_entry.
//
//Retorna 0 (cero) en caso de exito, o en caso de fallo, retorno el codigo correspondiente.
static int batadv_v_gw_dump_entry(struct sk_buff *msg, u32 portid, u32 seq,
				  struct batadv_priv *bat_priv,
				  struct batadv_gw_node *gw_node)
{
	//Declaracion de variables del metodo.
	struct batadv_neigh_ifinfo *router_ifinfo = NULL;
	struct batadv_neigh_node *router;
	struct batadv_gw_node *curr_gw;
	int ret = -EINVAL;
	void *hdr;

	//Obtengo el vecino que deberia ser enrutador para el orig_node
	router = batadv_orig_router_get(gw_node->orig_node, BATADV_IF_DEFAULT);
	if (!router)
		//En caso de error, libero los recursos y retorno el codigo 22 (argumento invalido).
		goto out;

	//Obtengo su informacion del vecino por la interfaz de salida
	router_ifinfo = batadv_neigh_ifinfo_get(router, BATADV_IF_DEFAULT);
	
	if (!router_ifinfo)
		//En caso de error, libero los recursos y retorno el codigo 22 (argumento invalido).
		goto out;
	//obtengo el GW actual 
	curr_gw = batadv_gw_get_selected_gw_node(bat_priv);
	
	//Creo un encabezado generico para el mensaje
	hdr = genlmsg_put(msg, portid, seq, &batadv_netlink_family,
			  NLM_F_MULTI, BATADV_CMD_GET_GATEWAYS);
	//Si fallo en la generacion del mismo, seteo el codigo de error ( 55 - "No buffer space available") y libero los recursos utilizados.
	if (!hdr) {
		ret = -ENOBUFS;
		goto out;
	}
	
	//Seteo el numero mensaje de error
	ret = -EMSGSIZE;

	//Agrega un atributo al buffer socket(gw_node->orig_node->orig)
	//Agrega un atributo u32 al buffer socket(router_ifinfo->bat_v.throughput)
	//Agrega un atributo al burffer socket(router->addr)
	//Agrega un atributo al buffer socket(router->if_incoming->net_dev->name)
	//Agrega un atributo u32 al buffer socket(gw_node->bandwidth_down)
	//Agrega un atributo u32 al buffer socket(gw_node->bandwidth_up)
	if (curr_gw == gw_node) {
		//agrego al mensaje
		if (nla_put_flag(msg, BATADV_ATTR_FLAG_BEST)) {
			genlmsg_cancel(msg, hdr);
			goto out;
		}
	}

	if (nla_put(msg, BATADV_ATTR_ORIG_ADDRESS, ETH_ALEN,
		    gw_node->orig_node->orig)) {
		genlmsg_cancel(msg, hdr);
		goto out;
	}

	if (nla_put_u32(msg, BATADV_ATTR_THROUGHPUT,
			router_ifinfo->bat_v.throughput)) {
		genlmsg_cancel(msg, hdr);
		goto out;
	}

	if (nla_put(msg, BATADV_ATTR_ROUTER, ETH_ALEN, router->addr)) {
		genlmsg_cancel(msg, hdr);
		goto out;
	}

	if (nla_put_string(msg, BATADV_ATTR_HARD_IFNAME,
			   router->if_incoming->net_dev->name)) {
		genlmsg_cancel(msg, hdr);
		goto out;
	}

	if (nla_put_u32(msg, BATADV_ATTR_BANDWIDTH_DOWN,
			gw_node->bandwidth_down)) {
		genlmsg_cancel(msg, hdr);
		goto out;
	}

	if (nla_put_u32(msg, BATADV_ATTR_BANDWIDTH_UP, gw_node->bandwidth_up)) {
		genlmsg_cancel(msg, hdr);
		goto out;
	}

	genlmsg_end(msg, hdr);
	ret = 0;

//libero los recursos y retorno.
out:
	if (router_ifinfo)
		batadv_neigh_ifinfo_put(router_ifinfo);
	if (router)
		batadv_neigh_node_put(router);
	return ret;
}

/**
 * batadv_v_gw_dump - Dump gateways into a message
 * @msg: Netlink message to dump into
 * @cb: Control block containing additional options
 * @bat_priv: The bat priv with all the soft interface information
 */
//La funcion "batadv_v_gw_dump" recorre la lista de nodos gw y por cada uno de ellos crea un mensaje 
//llamando al metodo batadv_v_gw_dump_entry.
//
//No es invocada en ninguna funcion, solo se utiliza en la inicializacion del struct de bat_v.
//No retorna valores
static void batadv_v_gw_dump(struct sk_buff *msg, struct netlink_callback *cb,
			     struct batadv_priv *bat_priv)
{
	//Obtengo el puerto
	int portid = NETLINK_CB(cb->skb).portid;
	struct batadv_gw_node *gw_node;
	int idx_skip = cb->args[0];
	int idx = 0;

	//Bloqueo los recursos para no generar inconsistencias
	rcu_read_lock();
	hlist_for_each_entry_rcu(gw_node, &bat_priv->gw.gateway_list, list) {
		if (idx++ < idx_skip)
			continue;
		//genero un mensaje para cada gateway
		if (batadv_v_gw_dump_entry(msg, portid, cb->nlh->nlmsg_seq,
					   bat_priv, gw_node)) {
			// en caso de error, libero el bloqueo y retorno.
			idx_skip = idx - 1;
			goto unlock;
		}
	}

	idx_skip = idx;
unlock:
	rcu_read_unlock();
	//Libero el bloqueo
	
	cb->args[0] = idx_skip;
}

static struct batadv_algo_ops batadv_batman_v __read_mostly = {
	.name = "BATMAN_V",
	.iface = {
		.activate = batadv_v_iface_activate,
		.enable = batadv_v_iface_enable,
		.disable = batadv_v_iface_disable,
		.update_mac = batadv_v_iface_update_mac,
		.primary_set = batadv_v_primary_iface_set,
	},
	.neigh = {
		.hardif_init = batadv_v_hardif_neigh_init,
		.cmp = batadv_v_neigh_cmp,
		.is_similar_or_better = batadv_v_neigh_is_sob,
#ifdef CONFIG_BATMAN_ADV_DEBUGFS
		.print = batadv_v_neigh_print,
#endif
		.dump = batadv_v_neigh_dump,
	},
	.orig = {
#ifdef CONFIG_BATMAN_ADV_DEBUGFS
		.print = batadv_v_orig_print,
#endif
		.dump = batadv_v_orig_dump,
	},
	.gw = {
		.init_sel_class = batadv_v_init_sel_class,
		.store_sel_class = batadv_v_store_sel_class,
		.show_sel_class = batadv_v_show_sel_class,
		.get_best_gw_node = batadv_v_gw_get_best_gw_node,
		.is_eligible = batadv_v_gw_is_eligible,
#ifdef CONFIG_BATMAN_ADV_DEBUGFS
		.print = batadv_v_gw_print,
#endif
		.dump = batadv_v_gw_dump,
	},
};

/**
 * batadv_v_hardif_init - initialize the algorithm specific fields in the
 *  hard-interface object
 * @hard_iface: the hard-interface to initialize
 */
void batadv_v_hardif_init(struct batadv_hard_iface *hard_iface)
{
	/* enable link throughput auto-detection by setting the throughput
	 * override to zero
	 */
	atomic_set(&hard_iface->bat_v.throughput_override, 0);
	atomic_set(&hard_iface->bat_v.elp_interval, 500);
}

/**
 * batadv_v_mesh_init - initialize the B.A.T.M.A.N. V private resources for a
 *  mesh
 * @bat_priv: the object representing the mesh interface to initialise
 *
 * Return: 0 on success or a negative error code otherwise
 */
int batadv_v_mesh_init(struct batadv_priv *bat_priv)
{
	int ret = 0;

	ret = batadv_v_ogm_init(bat_priv);
	if (ret < 0)
		return ret;

	return 0;
}

/**
 * batadv_v_mesh_free - free the B.A.T.M.A.N. V private resources for a mesh
 * @bat_priv: the object representing the mesh interface to free
 */
void batadv_v_mesh_free(struct batadv_priv *bat_priv)
{
	batadv_v_ogm_free(bat_priv);
}

/**
 * batadv_v_init - B.A.T.M.A.N. V initialization function
 *
 * Description: Takes care of initializing all the subcomponents.
 * It is invoked upon module load only.
 *
 * Return: 0 on success or a negative error code otherwise
 */
int __init batadv_v_init(void)
{
	int ret;

	/* B.A.T.M.A.N. V echo location protocol packet  */
	ret = batadv_recv_handler_register(BATADV_ELP,
					   batadv_v_elp_packet_recv);
	if (ret < 0)
		return ret;

	ret = batadv_recv_handler_register(BATADV_OGM2,
					   batadv_v_ogm_packet_recv);
	if (ret < 0)
		goto elp_unregister;

	ret = batadv_algo_register(&batadv_batman_v);
	if (ret < 0)
		goto ogm_unregister;

	return ret;

ogm_unregister:
	batadv_recv_handler_unregister(BATADV_OGM2);

elp_unregister:
	batadv_recv_handler_unregister(BATADV_ELP);

	return ret;
}

