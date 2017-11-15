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

/** This enums have been used in the file: **/

/**
 * enum batadv_nl_commands - supported batman-adv netlink commands
 *
 * @BATADV_CMD_UNSPEC: unspecified command to catch errors
 * @BATADV_CMD_GET_MESH_INFO: Query basic information about batman-adv device
 * @BATADV_CMD_TP_METER: Start a tp meter session
 * @BATADV_CMD_TP_METER_CANCEL: Cancel a tp meter session
 * @BATADV_CMD_GET_ROUTING_ALGOS: Query the list of routing algorithms.
 * @BATADV_CMD_GET_HARDIFS: Query list of hard interfaces
 * @BATADV_CMD_GET_TRANSTABLE_LOCAL: Query list of local translations
 * @BATADV_CMD_GET_TRANSTABLE_GLOBAL Query list of global translations
 * @BATADV_CMD_GET_ORIGINATORS: Query list of originators
 * @BATADV_CMD_GET_NEIGHBORS: Query list of neighbours
 * @BATADV_CMD_GET_GATEWAYS: Query list of gateways
 * @BATADV_CMD_GET_BLA_CLAIM: Query list of bridge loop avoidance claims
 * @BATADV_CMD_GET_BLA_BACKBONE: Query list of bridge loop avoidance backbones
 * @__BATADV_CMD_AFTER_LAST: internal use
 * @BATADV_CMD_MAX: highest used command number
 */

 /*enum batadv_hard_if_state {
	BATADV_IF_NOT_IN_USE,
	BATADV_IF_TO_BE_REMOVED,
	BATADV_IF_INACTIVE,
	BATADV_IF_ACTIVE,
	BATADV_IF_TO_BE_ACTIVATED,
	BATADV_IF_I_WANT_YOU,
};
*/ 

/**
 * enum batadv_nl_attrs - batman-adv netlink attributes
 *
 * @BATADV_ATTR_UNSPEC: unspecified attribute to catch errors
 * @BATADV_ATTR_VERSION: batman-adv version string
 * @BATADV_ATTR_ALGO_NAME: name of routing algorithm
 * @BATADV_ATTR_MESH_IFINDEX: index of the batman-adv interface
 * @BATADV_ATTR_MESH_IFNAME: name of the batman-adv interface
 * @BATADV_ATTR_MESH_ADDRESS: mac address of the batman-adv interface
 * @BATADV_ATTR_HARD_IFINDEX: index of the non-batman-adv interface
 * @BATADV_ATTR_HARD_IFNAME: name of the non-batman-adv interface
 * @BATADV_ATTR_HARD_ADDRESS: mac address of the non-batman-adv interface
 * @BATADV_ATTR_ORIG_ADDRESS: originator mac address
 * @BATADV_ATTR_TPMETER_RESULT: result of run (see batadv_tp_meter_status)
 * @BATADV_ATTR_TPMETER_TEST_TIME: time (msec) the run took
 * @BATADV_ATTR_TPMETER_BYTES: amount of acked bytes during run
 * @BATADV_ATTR_TPMETER_COOKIE: session cookie to match tp_meter session
 * @BATADV_ATTR_PAD: attribute used for padding for 64-bit alignment
 * @BATADV_ATTR_ACTIVE: Flag indicating if the hard interface is active
 * @BATADV_ATTR_TT_ADDRESS: Client MAC address
 * @BATADV_ATTR_TT_TTVN: Translation table version
 * @BATADV_ATTR_TT_LAST_TTVN: Previous translation table version
 * @BATADV_ATTR_TT_CRC32: CRC32 over translation table
 * @BATADV_ATTR_TT_VID: VLAN ID
 * @BATADV_ATTR_TT_FLAGS: Translation table client flags
 * @BATADV_ATTR_FLAG_BEST: Flags indicating entry is the best
 * @BATADV_ATTR_LAST_SEEN_MSECS: Time in milliseconds since last seen
 * @BATADV_ATTR_NEIGH_ADDRESS: Neighbour MAC address
 * @BATADV_ATTR_TQ: TQ to neighbour
 * @BATADV_ATTR_THROUGHPUT: Estimated throughput to Neighbour
 * @BATADV_ATTR_BANDWIDTH_UP: Reported uplink bandwidth
 * @BATADV_ATTR_BANDWIDTH_DOWN: Reported downlink bandwidth
 * @BATADV_ATTR_ROUTER: Gateway router MAC address
 * @BATADV_ATTR_BLA_OWN: Flag indicating own originator
 * @BATADV_ATTR_BLA_ADDRESS: Bridge loop avoidance claim MAC address
 * @BATADV_ATTR_BLA_VID: BLA VLAN ID
 * @BATADV_ATTR_BLA_BACKBONE: BLA gateway originator MAC address
 * @BATADV_ATTR_BLA_CRC: BLA CRC
 * @__BATADV_ATTR_AFTER_LAST: internal use
 * @NUM_BATADV_ATTR: total number of batadv_nl_attrs available
 * @BATADV_ATTR_MAX: highest attribute number currently defined
 */

/***********************************************************CODE*************************************************************/

/*
* batadv_v_iface_activate - this method changes the state of an interface to active mode.
*/
static void batadv_v_iface_activate(struct batadv_hard_iface *hard_iface)
{
	/**
	*	netdev_priv - access network device private data
	*	@dev: network device
	*
	* Get network device private data
	*/
	struct batadv_priv *bat_priv = netdev_priv(hard_iface->soft_iface);
	/**
	* struct batadv_hard_iface - network device known to batman-adv
	* @list: list node for batadv_hardif_list
	* @if_num: identificator of the interface
	* @if_status: status of the interface for batman-adv
	* @num_bcasts: number of payload re-broadcasts on this interface (ARQ)
	* @wifi_flags: flags whether this is (directly or indirectly) a wifi interface
	* @net_dev: pointer to the net_device
	* @hardif_obj: kobject of the per interface sysfs "mesh" directory
	* @refcount: number of contexts the object is used
	* @batman_adv_ptype: packet type describing packets that should be processed by
	*  batman-adv for this interface
	* @soft_iface: the batman-adv interface which uses this network interface
	* @rcu: struct used for freeing in an RCU-safe manner
	* @bat_iv: per hard-interface B.A.T.M.A.N. IV data
	* @bat_v: per hard-interface B.A.T.M.A.N. V data
	* @debug_dir: dentry for nc subdir in batman-adv directory in debugfs
	* @neigh_list: list of unique single hop neighbors via this interface
	* @neigh_list_lock: lock protecting neigh_list
	*/
	struct batadv_hard_iface *primary_if;
pr_info("Entro a batadv_v_iface_activate: interfaz numero %i\n", hard_iface->if_num);


    // This is one of the hard-interfaces assigned to this mesh interface
    //  becomes the primary interface
	primary_if = batadv_primary_if_get_selected(bat_priv);


	if (primary_if) {
		/**
		* batadv_v_elp_iface_activate - update the ELP buffer belonging to the given
		*  hard-interface
		* @primary_iface: the new primary interface
		* @hard_iface: interface holding the to-be-updated buffer
		*/
		batadv_v_elp_iface_activate(primary_if, hard_iface);
		/**
		* batadv_hardif_put - decrement the hard interface refcounter and possibly
		*  release it
		* @hard_iface: the hard interface to free
		*/
		batadv_hardif_put(primary_if);
	}

	/* B.A.T.M.A.N. V does not use any queuing mechanism, therefore it can
	 * set the interface as ACTIVE right away, without any risk of race
	 * condition
	 */
	 /* This is the possible states of network device known to batman-adv
	 	enum batadv_hard_if_state {
			BATADV_IF_NOT_IN_USE,
			BATADV_IF_TO_BE_REMOVED,
			BATADV_IF_INACTIVE,
			BATADV_IF_ACTIVE,
			BATADV_IF_TO_BE_ACTIVATED,
			BATADV_IF_I_WANT_YOU,
		};
	 */ 
	if (hard_iface->if_status == BATADV_IF_TO_BE_ACTIVATED)
		//Then the state is updated.
		hard_iface->if_status = BATADV_IF_ACTIVE;
}


static int batadv_v_iface_enable(struct batadv_hard_iface *hard_iface)
{
	int ret;

	/**
	* batadv_v_elp_iface_enable - setup the ELP interface private resources
	* @hard_iface: interface for which the data has to be prepared
	*
	* Return: 0 on success or a -ENOMEM in case of failure.
	*/
	ret = batadv_v_elp_iface_enable(hard_iface);
	if (ret < 0)
		return ret;
	/**
	* batadv_v_ogm_iface_enable - prepare an interface for B.A.T.M.A.N. V
	* @hard_iface: the interface to prepare
	*
	* Takes care of scheduling own OGM sending routine for this interface.
	*
	* Return: 0 on success or a negative error code otherwise
	*/
	ret = batadv_v_ogm_iface_enable(hard_iface);
	if (ret < 0)
		/**
		* batadv_v_elp_iface_disable - release ELP interface private resources
		* @hard_iface: interface for which the resources have to be released
		*/
		batadv_v_elp_iface_disable(hard_iface);

	return ret;
}

static void batadv_v_iface_disable(struct batadv_hard_iface *hard_iface)
{
	/**
	* batadv_v_elp_iface_disable - release ELP interface private resources
	* @hard_iface: interface for which the resources have to be released
	*/
	batadv_v_elp_iface_disable(hard_iface);
}

static void batadv_v_primary_iface_set(struct batadv_hard_iface *hard_iface)
{
	/**
	* batadv_v_elp_primary_iface_set - change internal data to reflect the new
	*  primary interface
	* @primary_iface: the new primary interface
	*/
	batadv_v_elp_primary_iface_set(hard_iface);

	/**
	* batadv_v_ogm_primary_iface_set - set a new primary interface
	* @primary_iface: the new primary interface
	*/
	batadv_v_ogm_primary_iface_set(hard_iface);
}

/**
 * batadv_v_iface_update_mac - react to hard-interface MAC address change
 * @hard_iface: the modified interface
 *
 * If the modified interface is the primary one, update the originator
 * address in the ELP and OGM messages to reflect the new MAC address.
 */
static void batadv_v_iface_update_mac(struct batadv_hard_iface *hard_iface)
{
	//network device known to batman-adv
	struct batadv_priv *bat_priv = netdev_priv(hard_iface->soft_iface);
	struct batadv_hard_iface *primary_if;

	// This is one of the hard-interfaces assigned to this mesh interface
    //  becomes the primary interface
	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (primary_if != hard_iface)
		goto out;
	// change internal data to reflect the new  primary interface and set a new primary interface
	batadv_v_primary_iface_set(hard_iface);
out:
	if (primary_if)
	/**
	* batadv_hardif_put - decrement the hard interface refcounter and possibly
	*  release it
	* @hard_iface: the hard interface to free
	*/
		batadv_hardif_put(primary_if);
}

//initialize the neigh node
static void 
batadv_v_hardif_neigh_init(struct batadv_hardif_neigh_node *hardif_neigh)
{
	ewma_throughput_init(&hardif_neigh->bat_v.throughput);
	// initializes the linked list pointers within the work_t structure
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
static void
batadv_v_orig_print_neigh(struct batadv_orig_node *orig_node,
			  struct batadv_hard_iface *if_outgoing,
			  struct seq_file *seq)
{
	struct batadv_neigh_node *neigh_node;
	struct batadv_neigh_ifinfo *n_ifinfo;
	

	/**
	* hlist_for_each_entry_rcu - iterate over rcu list of given type
	* @pos:	the type * to use as a loop cursor.
	* @head:	the head for your list.
	* @member:	the name of the hlist_node within the struct.
	*
	* This list-traversal primitive may safely run concurrently with
	* the _rcu list-mutation primitives such as hlist_add_head_rcu()
	* as long as the traversal is guarded by rcu_read_lock().
	*/
	/*#define hlist_for_each_entry_rcu(pos, head, member)			\
	for (pos = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))*/
	hlist_for_each_entry_rcu(neigh_node, &orig_node->neigh_list, list) {
		/**
		* batadv_neigh_ifinfo_get - find the ifinfo from an neigh_node
		* @neigh: the neigh node to be queried
		* @if_outgoing: the interface for which the ifinfo should be acquired
		*
		* The object is returned with refcounter increased by 1.
		*
		* Return: the requested neigh_ifinfo or NULL if not found
		*/
		n_ifinfo = batadv_neigh_ifinfo_get(neigh_node, if_outgoing);
		if (!n_ifinfo)
			continue;

		seq_printf(seq, " %pM (%9u.%1u)",
			   neigh_node->addr,
			   n_ifinfo->bat_v.throughput / 10,
			   n_ifinfo->bat_v.throughput % 10);
		/**
		* batadv_neigh_ifinfo_put - decrement the refcounter and possibly release
		*  the neigh_ifinfo
		* @neigh_ifinfo: the neigh_ifinfo object to release
		*/
		batadv_neigh_ifinfo_put(n_ifinfo);
	}
}

/**
 * batadv_v_hardif_neigh_print - print a single ELP neighbour node
 * @seq: neighbour table seq_file struct
 * @hardif_neigh: hardif neighbour information
 */
static void
batadv_v_hardif_neigh_print(struct seq_file *seq,
			    struct batadv_hardif_neigh_node *hardif_neigh)
{
	int last_secs, last_msecs;
	u32 throughput;
	/*
	* Convert jiffies to milliseconds and back.
	*
	* Avoid unnecessary multiplications/divisions in the
	* two most common HZ cases:
	*/
	last_secs = jiffies_to_msecs(jiffies - hardif_neigh->last_seen) / 1000;
	last_msecs = jiffies_to_msecs(jiffies - hardif_neigh->last_seen) % 1000;

	throughput = ewma_throughput_read(&hardif_neigh->bat_v.throughput);

	seq_printf(seq, "%pM %4i.%03is (%9u.%1u) [%10s]\n",
		   hardif_neigh->addr, last_secs, last_msecs, throughput / 10,
		   throughput % 10, hardif_neigh->if_incoming->net_dev->name);
}

/**
 * batadv_v_neigh_print - print the single hop neighbour list
 * @bat_priv: the bat priv with all the soft interface information
 * @seq: neighbour table seq_file struct
 */
static void batadv_v_neigh_print(struct batadv_priv *bat_priv,
				 struct seq_file *seq)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct batadv_hardif_neigh_node *hardif_neigh;
	struct batadv_hard_iface *hard_iface;
	int batman_count = 0;

	seq_puts(seq,
		 "  Neighbor        last-seen ( throughput) [        IF]\n");

	//obtain the lock.
	rcu_read_lock();

	/**
	* list_for_each_entry	-	iterate over list of given type
	* @pos:	the type * to use as a loop cursor.
	* @head:	the head for your list.
	* @member:	the name of the list_head within the struct.
	*/
	/*#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
		&pos->member != (head);					\
		pos = list_next_entry(pos, member))*/
	list_for_each_entry_rcu(hard_iface, &batadv_hardif_list, list) {
		if (hard_iface->soft_iface != net_dev)
			continue;

		hlist_for_each_entry_rcu(hardif_neigh,
					 &hard_iface->neigh_list, list) {
			//print a single ELP neighbour node
			batadv_v_hardif_neigh_print(seq, hardif_neigh);
			batman_count++;
		}
	}
	//release the lock
	rcu_read_unlock();

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
static int
batadv_v_neigh_dump_neigh(struct sk_buff *msg, u32 portid, u32 seq,
			  struct batadv_hardif_neigh_node *hardif_neigh)
{
	void *hdr;
	unsigned int last_seen_msecs;
	u32 throughput;
	//Convert jiffies to milliseconds and back.
	last_seen_msecs = jiffies_to_msecs(jiffies - hardif_neigh->last_seen);
	throughput = ewma_throughput_read(&hardif_neigh->bat_v.throughput);
	throughput = throughput * 100;
	/**
	* genlmsg_put - Add generic netlink header to netlink message
	* @skb: socket buffer holding the message
	* @portid: netlink portid the message is addressed to
	* @seq: sequence number (usually the one of the sender)
	* @family: generic netlink family
	* @flags: netlink message flags
	* @cmd: generic netlink command --> supported batman-adv netlink commands
	*
	* Returns pointer to user specific header
	*/
	hdr = genlmsg_put(msg, portid, seq, &batadv_netlink_family, NLM_F_MULTI,
			  BATADV_CMD_GET_NEIGHBORS);
	if (!hdr)
		// retuns this message: /* No buffer space available */
		return -ENOBUFS;

		/**
		* nla_put - Add a netlink attribute to a socket buffer
		* @skb: socket buffer to add attribute to
		* @attrtype: attribute type
		* @attrlen: length of attribute payload
		* @data: head of attribute payload
		*
		* Returns -EMSGSIZE if the tailroom of the skb is insufficient to store
		* the attribute header and payload.
		*/
	if (nla_put(msg, BATADV_ATTR_NEIGH_ADDRESS, ETH_ALEN,
			hardif_neigh->addr) ||
		/**
		* nla_put_u32 - Add a u32 netlink attribute to a socket buffer
		* @skb: socket buffer to add attribute to
		* @attrtype: attribute type
		* @value: numeric value
		*/
	    nla_put_u32(msg, BATADV_ATTR_HARD_IFINDEX,
			hardif_neigh->if_incoming->net_dev->ifindex) ||
	    nla_put_u32(msg, BATADV_ATTR_LAST_SEEN_MSECS,
			last_seen_msecs) ||
	    nla_put_u32(msg, BATADV_ATTR_THROUGHPUT, throughput))
		goto nla_put_failure;

	/**
	* genlmsg_end - Finalize a generic netlink message
	* @skb: socket buffer the message is stored in
	* @hdr: user specific header
	*/
	genlmsg_end(msg, hdr);
	return 0;

 nla_put_failure:
	/**
	* genlmsg_cancel - Cancel construction of a generic netlink message
	* @skb: socket buffer the message is stored in
	* @hdr: generic netlink message header
	*/
	genlmsg_cancel(msg, hdr);
	// return this this error: /* Message too long */
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
static int
batadv_v_neigh_dump_hardif(struct sk_buff *msg, u32 portid, u32 seq,
			   struct batadv_priv *bat_priv,
			   struct batadv_hard_iface *hard_iface,
			   int *idx_s)
{
	struct batadv_hardif_neigh_node *hardif_neigh;
	int idx = 0;

	//iterate over list of given type
	hlist_for_each_entry_rcu(hardif_neigh,
				 &hard_iface->neigh_list, list) {
		if (idx++ < *idx_s)
			continue;
		//Dump a neighbour into a message
		if (batadv_v_neigh_dump_neigh(msg, portid, seq, hardif_neigh)) {
			*idx_s = idx - 1;
			// return this this error: /* Message too long */
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
static void
batadv_v_neigh_dump(struct sk_buff *msg, struct netlink_callback *cb,
		    struct batadv_priv *bat_priv,
		    struct batadv_hard_iface *single_hardif)
{
	struct batadv_hard_iface *hard_iface;
	int i_hardif = 0;
	int i_hardif_s = cb->args[0];
	int idx = cb->args[1];
	//Macro: #define NETLINK_CB(skb)		(*(struct netlink_skb_parms*)&((skb)->cb))
	int portid = NETLINK_CB(cb->skb).portid;

	//obtain the lock
	rcu_read_lock();
	if (single_hardif) {
		if (i_hardif_s == 0) {
			//Dump the  neighbours of a hard interface  into a message
			if (batadv_v_neigh_dump_hardif(msg, portid,
						       cb->nlh->nlmsg_seq,
						       bat_priv, single_hardif,
						       &idx) == 0)
				i_hardif++;
		}
	} else {
		list_for_each_entry_rcu(hard_iface, &batadv_hardif_list, list) {
			if (hard_iface->soft_iface != bat_priv->soft_iface)
				continue;

			if (i_hardif++ < i_hardif_s)
				continue;
			//Dump the  neighbours of a hard interface  into a message
			if (batadv_v_neigh_dump_hardif(msg, portid,
						       cb->nlh->nlmsg_seq,
						       bat_priv, hard_iface,
						       &idx)) {
				i_hardif--;
				break;
			}
		}
	}
	//release the lock
	rcu_read_unlock();

	//update  of  Control block 
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

	seq_puts(seq,
		 "  Originator      last-seen ( throughput)           Nexthop [outgoingIF]:   Potential nexthops ...\n");

	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];

		//obtain the lock
		rcu_read_lock();
		hlist_for_each_entry_rcu(orig_node, head, hash_entry) {
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
			neigh_node = batadv_orig_router_get(orig_node,
							    if_outgoing);
			if (!neigh_node)
				continue;
			//find the ifinfo from an neigh_node
			n_ifinfo = batadv_neigh_ifinfo_get(neigh_node,
							   if_outgoing);
			if (!n_ifinfo)
				goto next;

			last_seen_jiffies = jiffies - orig_node->last_seen;
			last_seen_msecs = jiffies_to_msecs(last_seen_jiffies);
			last_seen_secs = last_seen_msecs / 1000;
			last_seen_msecs = last_seen_msecs % 1000;

			seq_printf(seq, "%pM %4i.%03is (%9u.%1u) %pM [%10s]:",
				   orig_node->orig, last_seen_secs,
				   last_seen_msecs,
				   n_ifinfo->bat_v.throughput / 10,
				   n_ifinfo->bat_v.throughput % 10,
				   neigh_node->addr,
				   neigh_node->if_incoming->net_dev->name);
			//print neighbors for the originator table
			batadv_v_orig_print_neigh(orig_node, if_outgoing, seq);
			seq_puts(seq, "\n");
			batman_count++;

next:
			/**
			* batadv_neigh_node_put - decrement the neighbors refcounter and possibly
			*  release it
			* @neigh_node: neigh neighbor to free
			* @ Return 1 if the object was removed, otherwise return 0.
			*/
			batadv_neigh_node_put(neigh_node);
			if (n_ifinfo)
				//decrement the refcounter and possibly release the neigh_ifinfo
				batadv_neigh_ifinfo_put(n_ifinfo);
		}
		//release the lock
		rcu_read_unlock();
	}

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
	//find the ifinfo from an neigh_node
	n_ifinfo = batadv_neigh_ifinfo_get(neigh_node, if_outgoing);
	if (!n_ifinfo)
		return 0;

	throughput = n_ifinfo->bat_v.throughput * 100;
	//decrement the refcounter and possibly release the neigh_ifinfo
	batadv_neigh_ifinfo_put(n_ifinfo);

	last_seen_msecs = jiffies_to_msecs(jiffies - orig_node->last_seen);

	if (if_outgoing != BATADV_IF_DEFAULT &&
	    if_outgoing != neigh_node->if_incoming)
		return 0;

	//Add generic netlink header to netlink message
	hdr = genlmsg_put(msg, portid, seq, &batadv_netlink_family, NLM_F_MULTI,
			  BATADV_CMD_GET_ORIGINATORS);
	if (!hdr)
		return -ENOBUFS;

		//Add a netlink attribute to a socket buffer
	if (nla_put(msg, BATADV_ATTR_ORIG_ADDRESS, ETH_ALEN, orig_node->orig) ||
	    nla_put(msg, BATADV_ATTR_NEIGH_ADDRESS, ETH_ALEN,
			neigh_node->addr) ||
		//Add a u32 netlink attribute to a socket buffer
	    nla_put_u32(msg, BATADV_ATTR_HARD_IFINDEX,
			neigh_node->if_incoming->net_dev->ifindex) ||
	    nla_put_u32(msg, BATADV_ATTR_THROUGHPUT, throughput) ||
	    nla_put_u32(msg, BATADV_ATTR_LAST_SEEN_MSECS,
			last_seen_msecs))
		goto nla_put_failure;

		/**
		* nla_put_flag - Add a flag netlink attribute to a socket buffer
		* @skb: socket buffer to add attribute to
		* @attrtype: attribute type
		*/
	if (best && nla_put_flag(msg, BATADV_ATTR_FLAG_BEST))
		goto nla_put_failure;

	/**
	* genlmsg_end - Finalize a generic netlink message
	* @msg: socket buffer the message is stored in
	* @hdr: user specific header
	*/
	genlmsg_end(msg, hdr);
	return 0;

 nla_put_failure:
    //Cancel construction of a generic netlink message
	genlmsg_cancel(msg, hdr);
	// return this this error: /* Message too long */
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

	//router to the originator depending on iface
	neigh_node_best = batadv_orig_router_get(orig_node, if_outgoing);
	if (!neigh_node_best)
		goto out;

	hlist_for_each_entry_rcu(neigh_node, &orig_node->neigh_list, list) {
		if (sub++ < *sub_s)
			continue;

		best = (neigh_node == neigh_node_best);

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
		if (batadv_v_orig_dump_subentry(msg, portid, seq, bat_priv,
						if_outgoing, orig_node,
						neigh_node, best)) {
			//decrement the neighbors refcounter and possibly release it
			batadv_neigh_node_put(neigh_node_best);

			*sub_s = sub - 1;
			// return this this error: /* Message too long */
			return -EMSGSIZE;
		}
	}

 out:
	if (neigh_node_best)
		//decrement the neighbors refcounter and possibly release it
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
static int
batadv_v_orig_dump_bucket(struct sk_buff *msg, u32 portid, u32 seq,
			  struct batadv_priv *bat_priv,
			  struct batadv_hard_iface *if_outgoing,
			  struct hlist_head *head, int *idx_s, int *sub)
{
	struct batadv_orig_node *orig_node;
	int idx = 0;

	//obtain the lock
	rcu_read_lock();
	hlist_for_each_entry_rcu(orig_node, head, hash_entry) {
		if (idx++ < *idx_s)
			continue;
		//Dump an originator entry into a message
		if (batadv_v_orig_dump_entry(msg, portid, seq, bat_priv,
					     if_outgoing, orig_node, sub)) {
			//release the lock
			rcu_read_unlock();
			*idx_s = idx - 1;
			// return this this error: /* Message too long */
			return -EMSGSIZE;
		}
	}
	//release the lock
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
static void
batadv_v_orig_dump(struct sk_buff *msg, struct netlink_callback *cb,
		   struct batadv_priv *bat_priv,
		   struct batadv_hard_iface *if_outgoing)
{
	struct batadv_hashtable *hash = bat_priv->orig_hash;
	struct hlist_head *head;
	int bucket = cb->args[0];
	int idx = cb->args[1];
	int sub = cb->args[2];
	//Macro: #define NETLINK_CB(skb)		(*(struct netlink_skb_parms*)&((skb)->cb))
	int portid = NETLINK_CB(cb->skb).portid;

	while (bucket < hash->size) {
		head = &hash->table[bucket];

		//Dump an originator bucket into a  message
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

// This function returns the difference of throughput between two neigh nodes.
static int batadv_v_neigh_cmp(struct batadv_neigh_node *neigh1,
			      struct batadv_hard_iface *if_outgoing1,
			      struct batadv_neigh_node *neigh2,
			      struct batadv_hard_iface *if_outgoing2)
{
	struct batadv_neigh_ifinfo *ifinfo1, *ifinfo2;
	int ret = 0;
	//find the ifinfo from an neigh_node 1
	ifinfo1 = batadv_neigh_ifinfo_get(neigh1, if_outgoing1);
	if (WARN_ON(!ifinfo1))
		goto err_ifinfo1;
	//find the ifinfo from an neigh_node 2
	ifinfo2 = batadv_neigh_ifinfo_get(neigh2, if_outgoing2);
	if (WARN_ON(!ifinfo2))
		goto err_ifinfo2;

	ret = ifinfo1->bat_v.throughput - ifinfo2->bat_v.throughput;
	//decrement the refcounter and possibly release the neigh_ifinfo of neigh node 1
	batadv_neigh_ifinfo_put(ifinfo2);
err_ifinfo2:
	//decrement the refcounter and possibly release the neigh_ifinfo of neigh node 2
	batadv_neigh_ifinfo_put(ifinfo1);
err_ifinfo1:
	return ret;
}
/* This function returns the boolean value that denotes if the 3/4 of throughput neigh
 * node one is minor than throughput neigh node two.
*/
static bool batadv_v_neigh_is_sob(struct batadv_neigh_node *neigh1,
				  struct batadv_hard_iface *if_outgoing1,
				  struct batadv_neigh_node *neigh2,
				  struct batadv_hard_iface *if_outgoing2)
{
	struct batadv_neigh_ifinfo *ifinfo1, *ifinfo2;
	u32 threshold;
	bool ret = false;
	//find the ifinfo from an neigh_node 1
	ifinfo1 = batadv_neigh_ifinfo_get(neigh1, if_outgoing1);
	if (WARN_ON(!ifinfo1))
		goto err_ifinfo1;
	//find the ifinfo from an neigh_node 2
	ifinfo2 = batadv_neigh_ifinfo_get(neigh2, if_outgoing2);
	if (WARN_ON(!ifinfo2))
		goto err_ifinfo2;

	threshold = ifinfo1->bat_v.throughput / 4;
	threshold = ifinfo1->bat_v.throughput - threshold;

	ret = ifinfo2->bat_v.throughput > threshold;
	//decrement the refcounter and possibly release the neigh_ifinfo of neigh node 2
	batadv_neigh_ifinfo_put(ifinfo2);
err_ifinfo2:
	//decrement the refcounter and possibly release the neigh_ifinfo of neigh node 1
	batadv_neigh_ifinfo_put(ifinfo1);
err_ifinfo1:
	return ret;
}

/**
 * batadv_v_init_sel_class - initialize GW selection class
 * @bat_priv: the bat priv with all the soft interface information
 */
static void batadv_v_init_sel_class(struct batadv_priv *bat_priv)
{
	/* set default throughput difference threshold to 5Mbps */
	atomic_set(&bat_priv->gw.sel_class, 50);
}

static ssize_t batadv_v_store_sel_class(struct batadv_priv *bat_priv,
					char *buff, size_t count)
{
	u32 old_class, class;

	/**
	* batadv_parse_throughput - parse supplied string buffer to extract throughput
	*  information
	* @net_dev: the soft interface net device
	* @buff: string buffer to parse
	* @description: text shown when throughput string cannot be parsed
	* @throughput: pointer holding the returned throughput information
	*
	* Return: false on parse error and true otherwise.
	*/
	if (!batadv_parse_throughput(bat_priv->soft_iface, buff,
				     "B.A.T.M.A.N. V GW selection class",
				     &class))
		return -EINVAL;

	old_class = atomic_read(&bat_priv->gw.sel_class);
	atomic_set(&bat_priv->gw.sel_class, class);

	if (old_class != class)
		/**
		* batadv_gw_reselect - force a gateway reselection
		* @bat_priv: the bat priv with all the soft interface information
		*
		* Set a flag to remind the GW component to perform a new gateway reselection.
		* However this function does not ensure that the current gateway is going to be
		* deselected. The reselection mechanism may elect the same gateway once again.
		*
		* This means that invoking batadv_gw_reselect() does not guarantee a gateway
		* change and therefore a uevent is not necessarily expected.
		*/
		batadv_gw_reselect(bat_priv);

	return count;
}

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
static int batadv_v_gw_throughput_get(struct batadv_gw_node *gw_node, u32 *bw)
{
	struct batadv_neigh_ifinfo *router_ifinfo = NULL;
	struct batadv_orig_node *orig_node;
	struct batadv_neigh_node *router;
	int ret = -1;

	orig_node = gw_node->orig_node;
	//router to the originator depending on iface
	router = batadv_orig_router_get(orig_node, BATADV_IF_DEFAULT);
	if (!router)
		goto out;

	//find the ifinfo from an neigh_node
	router_ifinfo = batadv_neigh_ifinfo_get(router, BATADV_IF_DEFAULT);
	if (!router_ifinfo)
		goto out;

	/* the GW metric is computed as the minimum between the path throughput
	 * to reach the GW itself and the advertised bandwidth.
	 * This gives us an approximation of the effective throughput that the
	 * client can expect via this particular GW node
	 */
	*bw = router_ifinfo->bat_v.throughput;
	//return minimum of two values, using the specified type.
	*bw = min_t(u32, *bw, gw_node->bandwidth_down);

	ret = 0;
out:
	if (router)
		//decrement the neighbors refcounter and possibly release it
		batadv_neigh_node_put(router);
	if (router_ifinfo)
		//decrement the refcounter and possibly release the neigh_ifinfo of neigh node
		batadv_neigh_ifinfo_put(router_ifinfo);

	return ret;
}

/**
 * batadv_v_gw_get_best_gw_node - retrieve the best GW node
 * @bat_priv: the bat priv with all the soft interface information
 *
 * Return: the GW node having the best GW-metric, NULL if no GW is known
 */
static struct batadv_gw_node *
batadv_v_gw_get_best_gw_node(struct batadv_priv *bat_priv)
{
	struct batadv_gw_node *gw_node, *curr_gw = NULL;
	u32 max_bw = 0, bw;

	//obtain the lock
	rcu_read_lock();
	hlist_for_each_entry_rcu(gw_node, &bat_priv->gw.gateway_list, list) {
		/**
		* kref_get_unless_zero - Increment refcount for object unless it is zero.
		* @kref: object.
		*
		* Return non-zero if the increment succeeded. Otherwise return 0.
		*
		* This function is intended to simplify locking around refcounting for
		* objects that can be looked up from a lookup structure, and which are
		* removed from that lookup structure in the object destructor.
		* Operations on such objects require at least a read lock around
		* lookup + kref_get, and a write lock around kref_put + remove from lookup
		* structure. Furthermore, RCU implementations become extremely tricky.
		* With a lookup followed by a kref_get_unless_zero *with return value check*
		* locking in the kref_put path can be deferred to the actual removal from
		* the lookup structure and RCU lookups become trivial.
		*/
		if (!kref_get_unless_zero(&gw_node->refcount))
			continue;
		 //retrieve the GW-bandwidth for a given GW
		if (batadv_v_gw_throughput_get(gw_node, &bw) < 0)
			goto next;

		if (curr_gw && (bw <= max_bw))
			goto next;

		if (curr_gw)
		/**
		* batadv_gw_node_put - decrement the gw_node refcounter and possibly release it
		* @gw_node: gateway node to free
		*/
			batadv_gw_node_put(curr_gw);

		curr_gw = gw_node;
		/**
		* kref_get - increment refcount for object.
		* @kref: object.
		*/
		kref_get(&curr_gw->refcount);
		max_bw = bw;

next:
		//decrement the gw_node refcounter and possibly release it
		batadv_gw_node_put(gw_node);
	}
	rcu_read_unlock();
	//release the lock

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
static bool batadv_v_gw_is_eligible(struct batadv_priv *bat_priv,
				    struct batadv_orig_node *curr_gw_orig,
				    struct batadv_orig_node *orig_node)
{
	struct batadv_gw_node *curr_gw, *orig_gw = NULL;
	u32 gw_throughput, orig_throughput, threshold;
	bool ret = false;

	threshold = atomic_read(&bat_priv->gw.sel_class);

	/**
	* batadv_gw_node_get - retrieve gateway node from list of available gateways
	* @bat_priv: the bat priv with all the soft interface information
	* @orig_node: originator announcing gateway capabilities
	*
	* Return: gateway node if found or NULL otherwise.
	*/
	curr_gw = batadv_gw_node_get(bat_priv, curr_gw_orig);
	if (!curr_gw) {
		ret = true;
		goto out;
	}

	//retrieve the GW-bandwidth for a given GW
	if (batadv_v_gw_throughput_get(curr_gw, &gw_throughput) < 0) {
		ret = true;
		goto out;
	}

	orig_gw = batadv_gw_node_get(bat_priv, orig_node);
	if (!orig_node)
		goto out;

	//retrieve gateway node from list of available gateways
	if (batadv_v_gw_throughput_get(orig_gw, &orig_throughput) < 0)
		goto out;

	if (orig_throughput < gw_throughput)
		goto out;

	if ((orig_throughput - gw_throughput) < threshold)
		goto out;

	batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
		   "Restarting gateway selection: better gateway found (throughput curr: %u, throughput new: %u)\n",
		   gw_throughput, orig_throughput);

	ret = true;
out:
	if (curr_gw)
		//decrement the gw_node refcounter and possibly release it
		batadv_gw_node_put(curr_gw);
	if (orig_gw)
		//decrement the gw_node refcounter and possibly release it
		batadv_gw_node_put(orig_gw);

	return ret;
}

#ifdef CONFIG_BATMAN_ADV_DEBUGFS
/* fails if orig_node has no router */
static int batadv_v_gw_write_buffer_text(struct batadv_priv *bat_priv,
					 struct seq_file *seq,
					 const struct batadv_gw_node *gw_node)
{
	struct batadv_gw_node *curr_gw;
	struct batadv_neigh_node *router;
	struct batadv_neigh_ifinfo *router_ifinfo = NULL;
	int ret = -1;

	//router to the originator depending on iface
	router = batadv_orig_router_get(gw_node->orig_node, BATADV_IF_DEFAULT);
	if (!router)
		goto out;

	//find the ifinfo from an neigh_node
	router_ifinfo = batadv_neigh_ifinfo_get(router, BATADV_IF_DEFAULT);
	if (!router_ifinfo)
		goto out;
		
	//SEGUIR POR ACA..,.
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
static void batadv_v_gw_print(struct batadv_priv *bat_priv,
			      struct seq_file *seq)
{
	struct batadv_gw_node *gw_node;
	int gw_count = 0;

	seq_puts(seq,
		 "      Gateway        ( throughput)           Nexthop [outgoingIF]: advertised uplink bandwidth\n");

	rcu_read_lock();
	hlist_for_each_entry_rcu(gw_node, &bat_priv->gw.gateway_list, list) {
		/* fails if orig_node has no router */
		if (batadv_v_gw_write_buffer_text(bat_priv, seq, gw_node) < 0)
			continue;

		gw_count++;
	}
	rcu_read_unlock();

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
static int batadv_v_gw_dump_entry(struct sk_buff *msg, u32 portid, u32 seq,
				  struct batadv_priv *bat_priv,
				  struct batadv_gw_node *gw_node)
{
	struct batadv_neigh_ifinfo *router_ifinfo = NULL;
	struct batadv_neigh_node *router;
	struct batadv_gw_node *curr_gw;
	int ret = -EINVAL;
	void *hdr;

	router = batadv_orig_router_get(gw_node->orig_node, BATADV_IF_DEFAULT);
	if (!router)
		goto out;

	router_ifinfo = batadv_neigh_ifinfo_get(router, BATADV_IF_DEFAULT);
	if (!router_ifinfo)
		goto out;

	curr_gw = batadv_gw_get_selected_gw_node(bat_priv);

	hdr = genlmsg_put(msg, portid, seq, &batadv_netlink_family,
			  NLM_F_MULTI, BATADV_CMD_GET_GATEWAYS);
	if (!hdr) {
		ret = -ENOBUFS;
		goto out;
	}

	ret = -EMSGSIZE;

	if (curr_gw == gw_node) {
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
static void batadv_v_gw_dump(struct sk_buff *msg, struct netlink_callback *cb,
			     struct batadv_priv *bat_priv)
{
	int portid = NETLINK_CB(cb->skb).portid;
	struct batadv_gw_node *gw_node;
	int idx_skip = cb->args[0];
	int idx = 0;

	rcu_read_lock();
	hlist_for_each_entry_rcu(gw_node, &bat_priv->gw.gateway_list, list) {
		if (idx++ < idx_skip)
			continue;

		if (batadv_v_gw_dump_entry(msg, portid, cb->nlh->nlmsg_seq,
					   bat_priv, gw_node)) {
			idx_skip = idx - 1;
			goto unlock;
		}
	}

	idx_skip = idx;
unlock:
	rcu_read_unlock();

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
