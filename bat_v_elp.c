/* Copyright (C) 2011-2017  B.A.T.M.A.N. contributors:
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

#include "bat_v_elp.h"
#include "main.h"

#include <linux/atomic.h>
#include <linux/byteorder/generic.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/fs.h>
#include <linux/if_ether.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <net/cfg80211.h>

#include "bat_algo.h"
#include "bat_v_ogm.h"
#include "hard-interface.h"
#include "log.h"
#include "originator.h"
#include "packet.h"
#include "routing.h"
#include "send.h"

/**
 * batadv_v_elp_start_timer - restart timer for ELP periodic work
 * @hard_iface: the interface for which the timer has to be reset
 */

// La funcion 'batadv_v_elp_start_timer' tiene la funcion de reiniciar el timer de retransmision de mensajes ELP.
// Cada nodo periódicamente (intervalo ELP) genera y transmite mensajes ELP para cada interfaz B.A.T.M.A.N. se está ejecutando.
// Esta recibe una referencia al nodo (interfaz) BATMAN para cual se va resetear el timer.

//Es invocada en:
//   -bat_v_elp.c:  batadv_v_elp_periodic_work 
//		 Al realizar la emision de los mensajes ELP en intervalos regulares se debe verificar si antes de emitir la interfaz, 
//      ademas de estar habilitada,tiene que estar activada. Si esta no posee dicho status, se llama a resetear el timer invocando 
//   	 a la funcion 'batadv_v_elp_start_timer'. Tambien es invocada en caso de que el buffer del mensaje ELP a enviar (que se presenta 
//	     con el campo elp_skb en el struct de la interfaz) se encuentre vacio, es decir, no se tenga el mensaje a replicar.
//   -bat_v_elp: batadv_v_elp_iface_enable 
//		 Esta funcion se utiliza al iniciar la  configuracion de los datos privados del struct la interfaz ELP (B.A.T.M.A.N),
//		 antes de iniciar el envio broadcast.
//
//Las secuencias de llamado a batadv_v_elp_start_timer son las siguientes
// -batadv_v_iface_enable-->batadv_v_elp_iface_enable-->batadv_v_elp_start_timer
// -batadv_v_elp_start_timer-->batadv_v_elp_iface_enable-->batadv_v_elp_periodic_work-->batadv_v_elp_start_timer
//
//Funcion estatica interna del archivo
static void batadv_v_elp_start_timer(struct batadv_hard_iface *hard_iface)
{
	unsigned int msecs;

	//Se utilizan dos macros:
    //#define BATADV_JITTER 20
	//#define atomic_read(v)		READ_ONCE((v)->counter)
	//Luego de utilizar estas dos macros, se prosigue a realizar el reset de la interfaz.
	//La unidad de tiempo que se utiliza es la de microsegundos, 
	//porque lo que se puede decir que cada cierta unidad de microsegundos el nodo  va a realizar esta transmision broadcast a todos sus vecinos.
	//Para resetear el timer, primero se realiza la resta entre el valor del intervalo de tiempo entre dos transmisiones ELP 
	//que forma parte del struct que representa a la interfaz como el atributo 'elp_interval' y  le resta BATADV_JITTER que es 20 unidades de msegs por defecto.
	//Este valor se encuentra en la macro en el Main de batman-adv como un parametro BATMAN.
	msecs = atomic_read(&hard_iface->bat_v.elp_interval) - BATADV_JITTER; 

	// 'prandom_u32' funcion del kernel
	//Al valor obtenido anteriormente se le adiciona el valor de un numero random modulo 40.
	msecs += prandom_u32() % (2 * BATADV_JITTER);

	//Se agrega la cola de trabajo correspondiente (utilizada para programar transmisiones ELP) a ejecutar con el delay calculado. 'queue_delayed_work' funcion del kernel.
	//Se utiliza una unidad 'jiffies' por que es el numero de tics que posee el timer del CPU. (Por cada interrupcion del timer, este se incrementa). Tambien llamado 'clock' o 'pulso'. 
	queue_delayed_work(batadv_event_workqueue, &hard_iface->bat_v.elp_wq,
			   msecs_to_jiffies(msecs));
}


/**
 * batadv_v_elp_get_throughput - get the throughput towards a neighbour
 * @neigh: the neighbour for which the throughput has to be obtained
 *
 * Return: The throughput towards the given neighbour in multiples of 100kpbs
 *         (a value of '1' equals to 0.1Mbps, '10' equals 1Mbps, etc).
 */

// La funcion 'batadv_v_elp_get_throughput' recibe la interfaz vecina para la cual se 
// debe obtener el rendimiento. Este rendimiento se obtiene en multiplos de 100kpbs, siguiendo la escala de : 1 = 0.1 Mbps, 10 = 1Mbps.
// Para ello se tiene en cuenta: 
//               		-si el usuario especificó un valor personalizado para esta interfaz, entonces se devuelve directamente
//				-si se trata de un dispositivo inalámbrico (WIFI), pregúntele a través de su rendimiento cfg80211 API
//				-si no puede encontrar informacion sobre la interfaz de interes, retorno 0 (cero). En caso contrario,
//				 retorno el valor del rendimiento esperado hacia esta estacion (sobre 100).
//				-si no es una interfaz wifi, verifique si este dispositivo proporciona datos a través de
//				 ethtool (por ejemplo, un adaptador de Ethernet). Luego obtiene la configuracion de la conexion y solicita su rendimiento (speed).
//				-Por ultimo, en caso de tener problemas tanto en la conexion inalambrica como en la ethernet, retorna un valor por defecto de 1 Mbps (seteado como macro en el main de B.A.T.M.A.N).
//
//Es invocada en:
//	-bat_v_elp.c: batadv_v_elp_throughput_metric_update
//	 Se utiliza para actualizar la métrica de rendimiento de un vecino de un solo salto.
//
//Las secuencias de llamados de 'batadv_v_elp_get_throughput' son los siguientes:
// -batadv_v_hardif_neigh_init-->batadv_v_elp_throughput_metric_update-->batadv_v_elp_get_throughput
//
//Retorna el rendimiento en multiplos de 100kpbs, siguiendo la escala de : 1 = 0.1 Mbps, 10 = 1Mbps.
static u32 batadv_v_elp_get_throughput(struct batadv_hardif_neigh_node *neigh)
{
	//Se obtiene el puntero a la interfaz entrante vecina (parametro)
	struct batadv_hard_iface *hard_iface = neigh->if_incoming;
	//Perteneciente al kernel
	struct ethtool_link_ksettings link_settings;
	// Esta estructura contine datos estrictamente de "alto nivel", y conoce
  	// casi cada estructura de datos utilizada en el módulo INET.
	struct net_device *real_netdev;
	struct station_info sinfo;
	u32 throughput;
	int ret;

	// si el usuario especificó un valor personalizado para esta interfaz, entonces se devuelve directamente
	throughput =  atomic_read(&hard_iface->bat_v.throughput_override);
	if (throughput != 0)
		return throughput;

	//Si se trata de un dispositivo inalámbrico (WIFI), pregúntele a través de su rendimiento cfg80211 API
	if (batadv_is_wifi_hardif(hard_iface)) {

		// si no soporta la version del driver del WIFI, va hacia el calculo del rendimiento por default
		if (!batadv_is_cfg80211_hardif(hard_iface))
			/* unsupported WiFi driver version */
			goto default_throughput;

		//obtengo el valor real
		real_netdev = batadv_get_real_netdev(hard_iface->net_dev);
		//en caso de se retorne NULL, es decir, que se produzca un error voy al culculo por default
		if (!real_netdev)
			goto default_throughput;
		/**
		* cfg80211_get_station - recupera información sobre una estación dada. Este posee los siguientes parametros:
		* @dev: el dispositivo donde se supone que la estación está conectada a
		* @mac_addr: la dirección MAC de la estación de interés
		* @sinfo: puntero a la estructura para completar con la información
		*
		* Devuelve 0 en caso de éxito y '&sinfo' se completa con la información disponible
		* de lo contrario devuelve un código de error negativo y el contenido de '&sinfo' tiene que ser
		* considerado indefinido.
		*/
		ret = cfg80211_get_station(real_netdev, neigh->addr, &sinfo);

		/**
		*	dev_put - release reference to device
		*	@dev: network device
		*
		* Release reference to device to allow it to be freed.
		*/
		//libera la referencia
		dev_put(real_netdev);
		//si ret retorna con un error debido a que no encuentra el archivo o directorio entonces..
		if (ret == -ENOENT) {
			/* El nodo ya no está asociado! Podría ser
			* posible eliminar este vecino Por ahora establece
			* la métrica de rendimiento a 0.
			*/
			return 0;
		}
		if (!ret)
			//si es distinto de null, retorno el valor del rendimiento esperado hacia esta estacion.
			return sinfo.expected_throughput / 100;
	}

	/* si no es una interfaz wifi, verifique si este dispositivo proporciona datos a través de
	* ethtool (por ejemplo, un adaptador de Ethernet)
	*/
	// 'memset': void *memset(void *s, int c, size_t n); --> Copia el valor de c (convertido a unsigned char)
	// en cada uno de los primeros n caracteres en el objeto apuntado por s.
	memset(&link_settings, 0, sizeof(link_settings));
	rtnl_lock();
	//  Helper interno del kernel para consultar un dispositivo ethtool_link_settings.
	ret = __ethtool_get_link_ksettings(hard_iface->net_dev, &link_settings);
	rtnl_unlock();
	if (ret == 0) {
		/* link characteristics might change over time */
		if (link_settings.base.duplex == DUPLEX_FULL)
			hard_iface->bat_v.flags |= BATADV_FULL_DUPLEX;
		else
			hard_iface->bat_v.flags &= ~BATADV_FULL_DUPLEX;
		//obtengo el rendimiento de la linea
		throughput = link_settings.base.speed;
		if (throughput && (throughput != SPEED_UNKNOWN))
			//realiza la conversion
			return throughput * 10;
	}

default_throughput:
	//el calculo por defecto
	if (!(hard_iface->bat_v.flags & BATADV_WARNING_DEFAULT)) {
		batadv_info(hard_iface->soft_iface,
			    "WiFi driver or ethtool info does not provide information about link speeds on interface %s, therefore defaulting to hardcoded throughput values of %u.%1u Mbps. Consider overriding the throughput manually or checking your driver.\n",
			    //El controlador WiFi o la información de ethtool no proporciona información sobre velocidades de enlace en la interfaz,
			    //por lo tanto, el valor de rendimiento codificado es de 1 Mbps. 
			    //Considere anular manualmente el rendimiento o verifique su controlador.",
			    hard_iface->net_dev->name,
			    BATADV_THROUGHPUT_DEFAULT_VALUE / 10,
			    BATADV_THROUGHPUT_DEFAULT_VALUE % 10);
		hard_iface->bat_v.flags |= BATADV_WARNING_DEFAULT;
	}

	/* if none of the above cases apply, return the base_throughput */
	//define BATADV_THROUGHPUT_DEFAULT_VALUE 10 /* 1 Mbps */ el valor que toma por defecto es de 1Mbps
	return BATADV_THROUGHPUT_DEFAULT_VALUE;
}

/**
 * batadv_v_elp_throughput_metric_update - worker updating the throughput metric
 *  of a single hop neighbour
 * @work: the work queue item
 */
// La funcion 'batadv_v_elp_throughput_metric_update' actualiza la metrica de rendimiento del nodo vecino en cuestion.
//
//Es invocada en:
//	- bat_v.c: batadv_v_hardif_neigh_init
//Las secuencias de llamados de 'batadv_v_elp_get_throughput' son los siguientes:
// -batadv_v_hardif_neigh_init-->batadv_v_elp_throughput_metric_update
//
//No tiene posee valor de retorno solo actualiza el rendimiento.
void batadv_v_elp_throughput_metric_update(struct work_struct *work)
{
	/**
	 * struct batadv_hardif_neigh_node_bat_v - B.A.T.M.A.N. V private neighbor
	 *  information
	 * @throughput: ewma link throughput towards this neighbor
	 * @elp_interval: time interval between two ELP transmissions
	 * @elp_latest_seqno: latest and best known ELP sequence number
	 * @last_unicast_tx: when the last unicast packet has been sent to this neighbor
	 * @metric_work: work queue callback item for metric update
	 */
	//struct que almacena la informacion privada del nodo vecino B.A.T.M.A.N
	struct batadv_hardif_neigh_node_bat_v *neigh_bat_v;
	
	/**
	 * struct batadv_hardif_neigh_node - unique neighbor per hard-interface
	 * @list: list node for batadv_hard_iface::neigh_list
	 * @addr: the MAC address of the neighboring interface
	 * @orig: the address of the originator this neighbor node belongs to
	 * @if_incoming: pointer to incoming hard-interface
	 * @last_seen: when last packet via this neighbor was received
	 * @bat_v: B.A.T.M.A.N. V private data
	 * @refcount: number of contexts the object is used
	 * @rcu: struct used for freeing in a RCU-safe manner
	 */
	//struct para contener la informacion sobre el nodo vecino (unique) por interfaz fisica.
	struct batadv_hardif_neigh_node *neigh;

	//obtengo el acceso a la informacion
	neigh_bat_v = container_of(work, struct batadv_hardif_neigh_node_bat_v,
				   metric_work);
	//obtengo el acceso a la informacion
	neigh = container_of(neigh_bat_v, struct batadv_hardif_neigh_node,
			     bat_v);

	//actualizo el rendimiento del nodo vecino en cuestion obteniendolo desde 'batadv_v_elp_get_throughput'
	ewma_throughput_add(&neigh->bat_v.throughput,
			    batadv_v_elp_get_throughput(neigh));

	/* decrement refcounter to balance increment performed before scheduling
	 * this task
	 */
	batadv_hardif_neigh_put(neigh);
}

/**
 * batadv_v_elp_wifi_neigh_probe - send link probing packets to a neighbour
 * @neigh: the neighbour to probe
 *
 * Sends a predefined number of unicast wifi packets to a given neighbour in
 * order to trigger the throughput estimation on this link by the RC algorithm.
 * Packets are sent only if there there is not enough payload unicast traffic
 * towards this neighbour..
 *
 * Return: True on success and false in case of error during skb preparation.
 */

// La funcion 'batadv_v_elp_wifi_neigh_probe' se encarga de envíar paquetes de prueba de enlace a un vecino. Por eso el parametro que 
// recibe es el nodo vecino a sondear.
//  Este envía un número predefinido de paquetes wifi unicast a un vecino dado en
// orden para activar la estimación de rendimiento en este enlace por el algoritmo RC.
// Los paquetes se envían solo si no hay suficiente tráfico de unicast de carga útil
// hacia este vecino.
//
//
//Es invocada en:
//		-bat_v_elp.c: batadv_v_elp_periodic_work
//		 La métrica de rendimiento se actualiza en cada paquete enviado. De esta forma, si
//		 el nodo está muerto y ya no envía paquetes, batman-adv todavía puede reaccionar oportunamente 
//		 a su muerte. Para probar este enlace es que se utiliza 'batadv_v_elp_wifi_neigh_probe'.
// 
//Las secuencias de llamados de 'batadv_v_elp_wifi_neigh_probe' son los siguientes:
//			bat_v.c: batadv_v_iface_enable-->batadv_v_elp_iface_enable-->batadv_v_elp_periodic_work-->batadv_v_elp_wifi_neigh_probe
//
//Retorna true en caso de éxito y false en caso de error durante la preparación de skb.
static bool
batadv_v_elp_wifi_neigh_probe(struct batadv_hardif_neigh_node *neigh)
{
	//Se obtiene el puntero a la interfaz entrante vecina (parametro)
	struct batadv_hard_iface *hard_iface = neigh->if_incoming;
	
	//obtengo la informacion privda de la intefaz vecina
	struct batadv_priv *bat_priv = netdev_priv(hard_iface->soft_iface);
	unsigned long last_tx_diff;
	struct sk_buff *skb;
	int probe_len, i;
	int elp_skb_len;

	/* this probing routine is for Wifi neighbours only */
	//Si no es una interfaz Wifi retorno true
	if (!batadv_is_wifi_hardif(hard_iface))
		return true;

	/* probe the neighbor only if no unicast packets have been sent
	 * to it in the last 100 milliseconds: this is the rate control
	 * algorithm sampling interval (minstrel). In this way, if not
	 * enough traffic has been sent to the neighbor, batman-adv can
	 * generate 2 probe packets and push the RC algorithm to perform
	 * the sampling
	 */
	/* Verifica al nodo vecino solo si no se han enviado paquetes unicast
	* en los últimos 100 milisegundos: este es el control de velocidad
	* intervalo de sampling del algoritmo ('minstrel'). De esta manera, si no
	* se ha enviado suficiente tráfico al nodo vecino, batman-adv puede
	* generar 2 paquetes de sondeo y pulsar el algoritmo RC para realizar
	* el muestreo
	*/
	//Extrae la cantidad de milisegundo desde la ultima vez que se han enviado paquetes
	last_tx_diff = jiffies_to_msecs(jiffies - neigh->bat_v.last_unicast_tx);
	//#define BATADV_ELP_PROBE_MAX_TX_DIFF 100 /* milliseconds */
	//Si este valor es menor o igual a 100 milisegundos retorno true.
	if (last_tx_diff <= BATADV_ELP_PROBE_MAX_TX_DIFF)
		return true;

	//setea 'probe_len' con el maximo entre el tamaño del elp paket y el minimo tamaño soportado que es 200 bytes
	probe_len = max_t(int, sizeof(struct batadv_elp_packet),
			  BATADV_ELP_MIN_PROBE_SIZE);

	//Itera 2 veces por nodo ya que 'BATADV_ELP_PROBES_PER_NODE' por definicion vale 2
	for (i = 0; i < BATADV_ELP_PROBES_PER_NODE; i++) {
		//obtengo la longitud de mensaje el mensaje ELP para enviar
		elp_skb_len = hard_iface->bat_v.elp_skb->len;
		//completo los bytes para que alcance al tamaño minimo.
		skb = skb_copy_expand(hard_iface->bat_v.elp_skb, 0,
				      probe_len - elp_skb_len,
				      GFP_ATOMIC);
		//si se produce algun error retorno false
		if (!skb)
			return false;

		/* Tell the skb to get as big as the allocated space (we want
		 * the packet to be exactly of that size to make the link
		 * throughput estimation effective.
		 */
		//setea al skb para que sea tan grande como el espacio asignado (esto se hace para que el
		//paquete sea exactamente de ese tamaño y la estimación del rendimiento del enlace sea efectiva.
		skb_put(skb, probe_len - hard_iface->bat_v.elp_skb->len);

		//logueo de la accion
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Sending unicast (probe) ELP packet on interface %s to %pM\n",
			   hard_iface->net_dev->name, neigh->addr);
		/**
		* batadv_send_skb_packet - send an already prepared packet
		* @skb: the packet to send
		* @hard_iface: the interface to use to send the broadcast packet
		* @dst_addr: the payload destination
		*
		* Send out an already prepared packet to the given neighbor or broadcast it
		* using the specified interface. Either hard_iface or neigh_node must be not
		* NULL.
		* If neigh_node is NULL, then the packet is broadcasted using hard_iface,
		* otherwise it is sent as unicast to the given neighbor.
		*
		* Regardless of the return value, the skb is consumed.
		*
		* Return: A negative errno code is returned on a failure. A success does not
		* guarantee the frame will be transmitted as it may be dropped due
		* to congestion or traffic shaping.
		*/
		//envia el packet ya preparado
		batadv_send_skb_packet(skb, hard_iface, neigh->addr);
	}
	//una vez enviados retorna TRUE.
	return true;
}

/**
 * batadv_v_elp_periodic_work - ELP periodic task per interface
 * @work: work queue item
 *
 * Emits broadcast ELP message in regular intervals.
 */
//
//La funcion 'batadv_v_elp_periodic_work' se encarga de emitir los mensajes ELP en modo broadcast a todos los vecinos si las condiciones estan dadas.
//Dichas condiciones son:
//			-si  el estado actual del mesh esta activado
//			-si la interfaz  no esta en uso o eliminada
//			-si la interfaz  se encuentra activada
//Una vez verificado todo esto, se envia en broadcast a todos sus nodos vecinos.
//
//Es invocada en:
//		-bat_v_elp.c: batadv_v_elp_iface_enable.
// 		 Se utiliza a la hora de habilitar las interfaces ELP.
//Las secuencias de llamados de 'batadv_v_elp_periodic_work' son los siguientes:
//			
//Emite los mensajes ELP en modo broadcast a todos los nodos vecinos de la interfaz en un periodo dado.
static bool

static void batadv_v_elp_periodic_work(struct work_struct *work)
{
	//declaracion de estructuras utilizadas en la funcion
	struct batadv_hardif_neigh_node *hardif_neigh;
	struct batadv_hard_iface *hard_iface;
	struct batadv_hard_iface_bat_v *bat_v;
	struct batadv_elp_packet *elp_packet;
	struct batadv_priv *bat_priv;
	struct sk_buff *skb;
	u32 elp_interval;

	//asignacion de las estructuras 
	bat_v = container_of(work, struct batadv_hard_iface_bat_v, elp_wq.work);
	hard_iface = container_of(bat_v, struct batadv_hard_iface, bat_v);
	//access network device private data
	//acceso a la informacion privada del dispositivo de red
	bat_priv = netdev_priv(hard_iface->soft_iface);

	// si  el estado actual del mesh es desativada sale de la funcion
	if (atomic_read(&bat_priv->mesh_state) == BATADV_MESH_DEACTIVATING)
		goto out;

	/*we are in the process of shutting this interface down*/
	// lo mismo ocurre si no esta en uso o ha sido elminada.
	if ((hard_iface->if_status == BATADV_IF_NOT_IN_USE) ||
	    (hard_iface->if_status == BATADV_IF_TO_BE_REMOVED))
		goto out;

	/* the interface was enabled but may not be ready yet */
	//en caso de que este habilida pero no activa, invoca a la funcion 'batadv_v_elp_start_timer' para reiniciar el timer
	if (hard_iface->if_status != BATADV_IF_ACTIVE)
		goto restart_timer;

	/**
 *	skb_copy	-	create private copy of an sk_buff
 *	@skb: buffer to copy
 *	@gfp_mask: allocation priority
 *
 *	Make a copy of both an &sk_buff and its data. This is used when the
 *	caller wishes to modify the data and needs a private copy of the
 *	data to alter. Returns %NULL on failure or the pointer to the buffer
 *	on success. The returned buffer has a reference count of 1.
 *
 *	As by-product this function converts non-linear &sk_buff to linear
 *	one, so that &sk_buff becomes completely private and caller is allowed
 *	to modify all the data of returned buffer. This means that this
 *	function is not recommended for use in circumstances when only
 *	header is going to be modified. Use pskb_copy() instead.
 */
	//realiza una copia del elp skb
	skb = skb_copy(hard_iface->bat_v.elp_skb, GFP_ATOMIC);
	// en caso de ocurrir un error en la creacion, se reiniciara  la interfaz, invocando a la funcion 'batadv_v_elp_start_timer'.
	if (!skb)
		goto restart_timer;

	//Una vez llegado a esta instancia se obtienen los datos de configuracion
	//los datos
	elp_packet = (struct batadv_elp_packet *)skb->data;
	//número actual de secuencia de ELP 
	elp_packet->seqno = htonl(atomic_read(&hard_iface->bat_v.elp_seqno));
	//tiempo de intervalo entre 2 transmisiones ELP
	elp_interval = atomic_read(&hard_iface->bat_v.elp_interval);
	elp_packet->elp_interval = htonl(elp_interval);

	//logueo de las acciones
	batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
		   "Sending broadcast ELP packet on interface %s, seqno %u\n",
		   hard_iface->net_dev->name,
		   atomic_read(&hard_iface->bat_v.elp_seqno));
	// call to the method: batadv_send_skb_packet,
	/**
	* batadv_send_skb_packet - send an already prepared packet
	* @skb: the packet to send
	* @hard_iface: the interface to use to send the broadcast packet
	* @dst_addr: the payload destination. In this case is
	* an unsigned char batadv_broadcast_addr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	* 
	* Send out an already prepared packet to the given neighbor or broadcast it
	* using the specified interface. Either hard_iface or neigh_node must be not
	* NULL.
	* If neigh_node is NULL, then the packet is broadcasted using hard_iface,
	* otherwise it is sent as unicast to the given neighbor.
	*
	* Regardless of the return value, the skb is consumed.
	*
	* Return: A negative errno code is returned on a failure. A success does not
	* guarantee the frame will be transmitted as it may be dropped due
	* to congestion or traffic shaping.
	*/
	// se envia en modo broadcast el mensaje ELP
	batadv_send_broadcast_skb(skb, hard_iface);

	atomic_inc(&hard_iface->bat_v.elp_seqno);

	/* The throughput metric is updated on each sent packet. This way, if a
	 * node is dead and no longer sends packets, batman-adv is still able to
	 * react timely to its death.
	 *
	 * The throughput metric is updated by following these steps:
	 * 1) if the hard_iface is wifi => send a number of unicast ELPs for
	 *    probing/sampling to each neighbor
	 * 2) update the throughput metric value of each neighbor (note that the
	 *    value retrieved in this step might be 100ms old because the
	 *    probing packets at point 1) could still be in the HW queue)
	 */
	//obtain the lock
	rcu_read_lock();
	//iterate over rcu list of given type
	/*#define hlist_for_each_entry_rcu(pos, head, member)			\
	for (pos = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))*/
	//Por cada uno de los nodos vecinos de la interfaz
	hlist_for_each_entry_rcu(hardif_neigh, &hard_iface->neigh_list, list) {
		
		//verifico que el enlace este en condiciones de transmitir
		if (!batadv_v_elp_wifi_neigh_probe(hardif_neigh))
			/* if something goes wrong while probing, better to stop
			 * sending packets immediately and reschedule the task
			 */
			break;

		//incrementa la refencias a menos que sea cero
		if (!kref_get_unless_zero(&hardif_neigh->refcount))
			continue;

		/* Reading the estimated throughput from cfg80211 is a task that
		 * may sleep and that is not allowed in an rcu protected
		 * context. Therefore schedule a task for that.
		 */
		//agrego a la cola de trabajo con el tiempo de delay de interfaz ('metric_word').
		queue_work(batadv_event_workqueue,
			   &hardif_neigh->bat_v.metric_work);
	}
	//release the lock
	rcu_read_unlock();

restart_timer:
	//restart timer for ELP periodic work
	// se reinicia el timer
	batadv_v_elp_start_timer(hard_iface);
out:
	return;
}

/**
 * batadv_v_elp_iface_enable - setup the ELP interface private resources
 * @hard_iface: interface for which the data has to be prepared
 *
 * Return: 0 on success or a -ENOMEM in case of failure.
 */
// La funcion 'batadv_v_elp_iface_enable' se encarga de configurar los recursos privados de la interfaz ELP.
// Esta configura el tamaño del mensaje, el mensaje mismo, el numero de secuencia, flags, version, tipo. Luego agrega a la cola 
//de trabajo la funcion 'batadv_v_elp_periodic_work', para luego reiniciar el timer.
//
// Es invocada en:
//		-bat_v_elp.c: batadv_v_iface_enable
// 		 De esta manera primero se emiten los paquetes ELP para luego continuar con los OMGs.
//
//Las secuencias de llamados de 'batadv_v_elp_iface_enable' son los siguientes:
//	-batadv_v_iface_enable-->batadv_v_elp_iface_enable
//
//Retorna 0, en caso de tener exito, y un mensaje de 'fuera de memoria' en caso de fallar.
int batadv_v_elp_iface_enable(struct batadv_hard_iface *hard_iface)
{
	//declaracion de variables 
	//paquete elp
	struct batadv_elp_packet *elp_packet;
	unsigned char *elp_buff;
	u32 random_seqno;
	size_t size;
	int res = -ENOMEM; //message: Out of Memory

	//#define ETH_HLEN	14		/* Total octets in header.	 */
	//#define NET_IP_ALIGN	2
	//#define BATADV_ELP_HLEN sizeof(struct batadv_elp_packet): lo reemplazo con el tamaño del struct 'batadv_elp_packet'.
	size = ETH_HLEN + NET_IP_ALIGN + BATADV_ELP_HLEN;
	// le asigno memoria al paquete elp_skb del tamaño obtenido
	hard_iface->bat_v.elp_skb = dev_alloc_skb(size);
	//Si hubo algun error retorno el mensaje de error: Fuera de memoria
	if (!hard_iface->bat_v.elp_skb)
		goto out;

	//ajusta el espacio libre del paquete
	skb_reserve(hard_iface->bat_v.elp_skb, ETH_HLEN + NET_IP_ALIGN);
	
	elp_buff = skb_put(hard_iface->bat_v.elp_skb, BATADV_ELP_HLEN);
	//completa con ceros
	elp_packet = (struct batadv_elp_packet *)elp_buff;
	memset(elp_packet, 0, BATADV_ELP_HLEN);

	//seteo el tipo  --> BATADV_ELP: echo location packets for B.A.T.M.A.N. V
	elp_packet->packet_type = BATADV_ELP;
	//seteo la version numero 15 --> BATADV_COMPAT_VERSION:  15
	elp_packet->version = BATADV_COMPAT_VERSION;

	/* randomize initial seqno to avoid collision */
	// aleatoriza el seqno (actual numero ELP de secuencia) inicial para evitar colisión
	get_random_bytes(&random_seqno, sizeof(random_seqno));
	atomic_set(&hard_iface->bat_v.elp_seqno, random_seqno);

	/* assume full-duplex by default */
	//supone full-duplex por defecto
	hard_iface->bat_v.flags |= BATADV_FULL_DUPLEX;

	/* warn the user (again) if there is no throughput data is available */
	//adverte al usuario (nuevamente) si no hay datos de rendimiento disponibles 
	hard_iface->bat_v.flags &= ~BATADV_WARNING_DEFAULT;

	//chequea si es un interfaz Wifi
	if (batadv_is_wifi_hardif(hard_iface))
		hard_iface->bat_v.flags &= ~BATADV_FULL_DUPLEX;

	//inicia a operar con la funcion 'batadv_v_elp_periodic_work' (con un retraso de 0, por defecto)
	INIT_DELAYED_WORK(&hard_iface->bat_v.elp_wq,
			  batadv_v_elp_periodic_work);
	//restart timer for ELP periodic work
	//reinicia el timer
	batadv_v_elp_start_timer(hard_iface);
	res = 0;

out:
	return res;
}

/**
 * batadv_v_elp_iface_disable - release ELP interface private resources
 * @hard_iface: interface for which the resources have to be released
 */
//La funcion 'batadv_v_elp_iface_disable' se encarga de liberar los recursos tomados por la interfaz ELP (memoria)
//
// Es invocada en:
//		-bat_v.c: batadv_v_iface_disable. Deshabilita la interfaz ELP (limpia memoria).
// 		-bat_v.c:  batadv_v_iface_enable . En el momento se habilita la emision de paquetes OGMs, en caso de ocurrir algun error 
//               en el llamado a ' batadv_v_ogm_iface_enable' se deshabilita la interfaz.
//
//Las secuencias de llamados de 'batadv_v_elp_iface_disable' son los siguientes:
//	-bat_v.c: declaracion del struct batadv_algo_ops-->batadv_v_iface_disable-->batadv_v_elp_iface_disable
//	-bat_v.c: declaracion del struct batadv_algo_ops-->batadv_v_iface_enable-->batadv_v_elp_iface_disable
//
//No posee valor de retorno
void batadv_v_elp_iface_disable(struct batadv_hard_iface *hard_iface)
{
	//cancela un trabajo retrasado y esperar a que termine (kernel).
	cancel_delayed_work_sync(&hard_iface->bat_v.elp_wq);
	//libera el buffer del mensaje
	dev_kfree_skb(hard_iface->bat_v.elp_skb);
	//setea a null el mismo
	hard_iface->bat_v.elp_skb = NULL;
}

/**
 * batadv_v_elp_iface_activate - update the ELP buffer belonging to the given
 *  hard-interface
 * @primary_iface: the new primary interface
 * @hard_iface: interface holding the to-be-updated buffer
 */
// La funcion 'batadv_v_elp_iface_activate' actualiza el buffer ELP, actualizando la interfaz fisica.
//
// Es invocada en:
//		-bat_v_elp.c: batadv_v_elp_primary_iface_set. Al cambiar la informacion interna de la nueva interfaz fisica.
//		-bat_v.c: batadv_v_iface_activate. Al activar la nueva interfaz fisica.
//
//Las secuencias de llamados de 'batadv_v_elp_iface_activate' son los siguientes:
//		-bat_v_elp.c: batadv_v_elp_primary_iface_set-->batadv_v_elp_iface_activate
//		-bat_v.c: batadv_v_iface_activate-->batadv_v_elp_iface_activate
//no posee valor de retorno.
void batadv_v_elp_iface_activate(struct batadv_hard_iface *primary_iface,
				 struct batadv_hard_iface *hard_iface)
{
	//Declaracion variables
	struct batadv_elp_packet *elp_packet;
	struct sk_buff *skb;

	//Si no contiene mensaje EPL, sale de la funcion.
	if (!hard_iface->bat_v.elp_skb)
		return;
	//pido el paquete
	skb = hard_iface->bat_v.elp_skb;
	//obtain the private data of ELP packet.
	//obtengo los privados datos del mismo (struct)
	elp_packet = (struct batadv_elp_packet *)skb->data;
	/**
	* ether_addr_copy - Copy an Ethernet address
	* @dst: Pointer to a six-byte array Ethernet address destination
	* @src: Pointer to a six-byte array Ethernet address source
	*
	* Please note: dst & src must both be aligned to u16.
	*/
	//this copies the source address of the ELP interface in the physical interface.
	//copio la direccion del origen del paquete en la direccion en la interfaz fisica
	ether_addr_copy(elp_packet->orig,
			primary_iface->net_dev->dev_addr);
}

/**
 * batadv_v_elp_primary_iface_set - change internal data to reflect the new
 *  primary interface
 * @primary_iface: the new primary interface
 */
//La funcion 'batadv_v_elp_primary_iface_set'  setea/actualiza las interfaces del mesh.
//
//Es invocada en: 
//		-bat_v.c :  batadv_v_primary_iface_set.
//
//Las secuencias de llamados de 'batadv_v_elp_iface_activate' son los siguientes:
//		-bat_v.c:  batadv_v_iface_update_mac->batadv_v_primary_iface_set-->batadv_v_elp_primary_iface_set.
//		-bat_v.c:  declaracion de 'struct batadv_algo_ops batadv_batman_v' -->batadv_v_primary_iface_set-->batadv_v_elp_primary_iface_set.
//no posee valor de retorno.
void batadv_v_elp_primary_iface_set(struct batadv_hard_iface *primary_iface)
{
	//Declaracion de estructuras
	struct batadv_hard_iface *hard_iface;

	/* update orig field of every elp iface belonging to this mesh */
	rcu_read_lock();
	//iterate over rcu list of given type
	/*#define hlist_for_each_entry_rcu(pos, head, member)			\
	for (pos = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))*/
	//Por cada una de las interfaces fisicas
	list_for_each_entry_rcu(hard_iface, &batadv_hardif_list, list) {
		//En caso de no coincidir con la interfaz primaria (nueva), salteo la interfaz
		if (primary_iface->soft_iface != hard_iface->soft_iface)
			continue;
		//update the ELP buffer belonging to the given hard-interface
		//actualizo la interfaz fisica
		batadv_v_elp_iface_activate(primary_iface, hard_iface);
	}
	rcu_read_unlock();
}

/**
 * batadv_v_elp_neigh_update - update an ELP neighbour node
 * @bat_priv: the bat priv with all the soft interface information
 * @neigh_addr: the neighbour interface address
 * @if_incoming: the interface the packet was received through
 * @elp_packet: the received ELP packet
 *
 * Updates the ELP neighbour node state with the data received within the new
 * ELP packet.
 */
// La funcion 'batadv_v_elp_neigh_update' actualiza el estado del nodo ELP vecino con la data recibida del nuevo paquete ELP.
//	
//Es invocada en:
//		-bat_v_elp.c: batadv_v_elp_packet_recv
// Las secuencias de llamados de 'batadv_v_elp_neigh_update' son los siguientes:
//		bat_v.c int __init batadv_v_init --> batadv_v_elp_packet_recv--> batadv_v_elp_neigh_update
//No poseo valor de retorno
static void batadv_v_elp_neigh_update(struct batadv_priv *bat_priv,
				      u8 *neigh_addr,
				      struct batadv_hard_iface *if_incoming,
				      struct batadv_elp_packet *elp_packet)

{
	//Declaracion de variables
	struct batadv_neigh_node *neigh;
	struct batadv_orig_node *orig_neigh;
	struct batadv_hardif_neigh_node *hardif_neigh;
	s32 seqno_diff;
	s32 elp_latest_seqno;
	

	/**
	* batadv_v_ogm_orig_get - retrieve and possibly create an originator node
	* @bat_priv: the bat priv with all the soft interface information
	* @addr: the address of the originator
	*
	* Return: the orig_node corresponding to the specified address. If such object
	* does not exist it is allocated here. In case of allocation failure returns
	* NULL.
	*/
	//obtengo el nodo originator correspondiente a la direccion especificada.
	orig_neigh = batadv_v_ogm_orig_get(bat_priv, elp_packet->orig);
	//si es nulo, entonces salgo de la funcion
	if (!orig_neigh)
		return;

	/**
	* batadv_neigh_node_get_or_create - retrieve or create a neigh node object
	* @orig_node: originator object representing the neighbour
	* @hard_iface: the interface where the neighbour is connected to
	* @neigh_addr: the mac address of the neighbour interface
	*
	* Return: the neighbour node if found or created or NULL otherwise.
	*/
	//obtengo el nodo vecino a partir de el nodo originator, la interfaz de conexion y la direccion mac del nodo vecino
	neigh = batadv_neigh_node_get_or_create(orig_neigh,
						if_incoming, neigh_addr);
	//si no lo puedo creo o encontrar
	if (!neigh)
		//libero el nodo originator obtenido anteriormente
		goto orig_free;
	
	/**
	* batadv_hardif_neigh_get - retrieve a hardif neighbour from the list
	* @hard_iface: the interface where this neighbour is connected to
	* @neigh_addr: the address of the neighbour
	*
	* Looks for and possibly returns a neighbour belonging to this hard interface.
	*
	* Return: neighbor when found. Othwerwise NULL
	*/
	//obtengo la interfaz fisica del nodo vecino
	hardif_neigh = batadv_hardif_neigh_get(if_incoming, neigh_addr);
	// si ocurre algun error..
	if (!hardif_neigh)
		//libero la estructura obtenida anteriormente
		goto neigh_free;

	//obtengo el ultimo valor de numero de secuencia
	elp_latest_seqno = hardif_neigh->bat_v.elp_latest_seqno;
	//calculo la direncia entre el numero de secuencia del paquete y el ultimo obtenido
	seqno_diff = ntohl(elp_packet->seqno) - elp_latest_seqno;

	/* known or older sequence numbers are ignored. However always adopt
	 * if the router seems to have been restarted.
	 */
	// Si dicha diferencia NO es menor a 1 o mayor que -64 (valor definido como macro de 'BATADV_ELP_MAX_AGE').
	if (seqno_diff < 1 && seqno_diff > -BATADV_ELP_MAX_AGE)
		//libero la interfaz fisica vecina
		goto hardif_free;

	//En caso contrario, actualizo la ultima visita del nodo vecino, de la interfaz fisica del vecino. Tambien setea el numero de secuencia y el intervalo de emision
	neigh->last_seen = jiffies;
	hardif_neigh->last_seen = jiffies;
	hardif_neigh->bat_v.elp_latest_seqno = ntohl(elp_packet->seqno);
	hardif_neigh->bat_v.elp_interval = ntohl(elp_packet->elp_interval);
//por ultimo libero los recursos utlizados
	
hardif_free:
	if (hardif_neigh)
		/**
		* batadv_hardif_neigh_put - decrement the hardif neighbors refcounter
		*  and possibly release it
		* @hardif_neigh: hardif neigh neighbor to free
		*/
		batadv_hardif_neigh_put(hardif_neigh);
neigh_free:
	if (neigh)
		/**
		* batadv_neigh_node_put - decrement the neighbors refcounter and possibly
		*  release it
		* @neigh_node: neigh neighbor to free
		*/
		batadv_neigh_node_put(neigh);
orig_free:
	if (orig_neigh)
		/**
		* batadv_orig_node_put - decrement the orig node refcounter and possibly
		*  release it
		* @orig_node: the orig node to free
		*/
		batadv_orig_node_put(orig_neigh);
}

/**
 * batadv_v_elp_packet_recv - main ELP packet handler
 * @skb: the received packet
 * @if_incoming: the interface this packet was received through
 *
 * Return: NET_RX_SUCCESS and consumes the skb if the packet was peoperly
 * processed or NET_RX_DROP in case of failure.
 */
// La funcion 'batadv_v_elp_packet_recv' cumple la funcion de control/gestion de la recepcion de los paquete ELP.
//
//Es invocada en:
//		-bat_v.c:  __init batadv_v_init. 
//		Se utiliza en la funcion de inicializacion de B.A.T.M.A.N. para setear la funcion encargada de la gestion de paquetes ELP.
//
//Las secuencias de llamados de 'batadv_v_elp_packet_recv' son los siguientes:
//		-bat_v.c:  __init batadv_v_init-->batadv_v_elp_packet_recv
int batadv_v_elp_packet_recv(struct sk_buff *skb,
			     struct batadv_hard_iface *if_incoming)
{
	//access to the private data
	//Declaracion e instanciacion de variables
	struct batadv_priv *bat_priv = netdev_priv(if_incoming->soft_iface);
	struct batadv_elp_packet *elp_packet;
	struct batadv_hard_iface *primary_if;

	//obtengo el encabezdo del mensaje
	struct ethhdr *ethhdr = (struct ethhdr *)skb_mac_header(skb);
	bool res;
	int ret = NET_RX_DROP; // message "packet dropped"

	/*	
	* Performs the following controls:
	*   -drop packet if it has not necessary minimum size 
	*	-packet with broadcast indication but unicast recipient
	*	-packet with invalid sender address
	*	-create a copy of the skb, if needed, to modify it
	* 	-change  of keep skb linear, if needed.
	*/
	/*
	* Realiza los siguientes controles:
	* 	-paquete de gotas si no tiene el tamaño mínimo necesario
	* 	-paquete con indicación de difusión pero destinatario de unidifusión
	* 	-packet con dirección de remitente no válida
	* 	-cree una copia del skb, si es necesario, para modificarlo
	* 	-cambio de mantener skb lineal, si es necesario.
	*/
	res = batadv_check_management_packet(skb, if_incoming, BATADV_ELP_HLEN);
	if (!res)
		//En caso de no cumplir con la validacion, libero los recursos tomados por el mensaje
		goto free_skb;

	/**
	* batadv_is_my_mac - check if the given mac address belongs to any of the real
	* interfaces in the current mesh
	* @bat_priv: the bat priv with all the soft interface information
	* @addr: the address to check
	*
	* Return: 'true' if the mac address was found, false otherwise.
	*/
	//corrobora si la dirección MAC dada pertenece a cualquiera de las interfaces reales en la malla actual
	if (batadv_is_my_mac(bat_priv, ethhdr->h_source))
		//En caso contrario, libero los recursos
		goto free_skb;

	/* did we receive a B.A.T.M.A.N. V ELP packet on an interface
	 * that does not have B.A.T.M.A.N. V ELP enabled ?
	 */
	//Pregunto por el algoritmo de ruteo utilizado en la interfaz mesh.En caso de no ser B.A.T.M.A.N, libero los recursos.
	if (strcmp(bat_priv->algo_ops->name, "BATMAN_V") != 0)
		goto free_skb;
	
	//obtengo ls datos del paquete (mensaje)
	elp_packet = (struct batadv_elp_packet *)skb->data;

	//#define batadv_dbg(type, bat_priv, arg...) \ _batadv_dbg(type, bat_priv, 0, ## arg)
	//logging de la accion realizada
	batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
		   "Received ELP packet from %pM seqno %u ORIG: %pM\n",
		   ethhdr->h_source, ntohl(elp_packet->seqno),
		   elp_packet->orig);
	// This is one of the hard-interfaces assigned to this mesh interface
    	//  becomes the primary interface
	//obtengo la interfaz primaria
	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (!primary_if)
		//si ocurre alun error, libero los recursos
		goto free_skb;
	//update an ELP neighbour node
	/actualizo el estado del nodo ELP vecino con la data recibida del nuevo paquete ELP.
	batadv_v_elp_neigh_update(bat_priv, ethhdr->h_source, if_incoming,
				  elp_packet);
	
	//seteo el exito de la operacion
	ret = NET_RX_SUCCESS; // message: “keep 'em coming, baby”
	/**
	* batadv_hardif_put - decrement the hard interface refcounter and possibly
	*  release it
	* @hard_iface: the hard interface to free
	*/
	batadv_hardif_put(primary_if);

free_skb:
	if (ret == NET_RX_SUCCESS)
		/**
		*	consume_skb - free an skbuff
		*	@skb: buffer to free
		*
		*	Drop a ref to the buffer and free it if the usage count has hit zero
		*	Functions identically to kfree_skb, but kfree_skb assumes that the frame
		*	is being dropped after a failure and notes that
		*/
		//libero el recurso
		consume_skb(skb);
	else
		/**
		*	kfree_skb - free an sk_buff
		*	@skb: buffer to free
		*
		*	Drop a reference to the buffer and free it if the usage count has
		*	hit zero.
		*/
		//libero recurso
		kfree_skb(skb);

	return ret;
}
