#include <linux/etherdevice.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <net/cfg80211.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");
MODULE_DESCRIPTION("virtual cfg80211 driver");

#define NAME_PREFIX "vcd"
#define NDEV_NAME NAME_PREFIX "%d"

#define MAX_PROBED_SSIDS 50

#define SCAN_TIMEOUT_MS 100 // millisecond

struct vcd_packet {
    int datalen;
    u8 data[ETH_DATA_LEN];
    struct list_head list;
};

enum vwifi_state { vcd_READY, vcd_SHUTDOWN };

/* There is only single vcd_context !!! */
struct vcd_context {
    struct mutex lock;
    /* Indicate the program state */
    enum vwifi_state state;
    /* List for maintaining all interfaces */
    struct list_head vi_list;
    /* List for maintaining multiple AP */
    struct list_head ap_list;
};

/* SME stands for "station management entity" */
enum sme_state { SME_DISCONNECTED, SME_CONNECTING, SME_CONNECTED };

/* Virtual interface */
struct vcd_vi {
    struct wireless_dev wdev;
    struct net_device *ndev;
    struct net_device_stats stats;

    size_t ssid_len;
    /* Currently connected BSS id */
    u8 bssid[ETH_ALEN];
    u8 ssid[IEEE80211_MAX_SSID_LEN];

    /* Head of received packet queue */
    struct list_head rx_queue;
    /* Store all vcd_vi which is in the same BSS (AP will be the head). */
    struct list_head bss_list;
    /* List entry for maintaining all vcd_vi, which can be access via
     * vcd->vi_list.
     */
    struct list_head list;

    struct mutex lock;

    /* Split logic for STA and AP mode */
    union {
        /* Structure for STA mode */
        struct {
            /* For the case the STA is going to roam to another BSS */
            u8 req_ssid[IEEE80211_MAX_SSID_LEN];

            struct cfg80211_scan_request *scan_request;
            enum sme_state sme_state; /* connection information */
            unsigned long
                conn_time; /* last connection time to a AP (in jiffies) */
            unsigned long active_time; /* last tx/rx time (in jiffies) */
            u16 disconnect_reason_code;

            struct timer_list scan_timeout;
            struct work_struct ws_connect, ws_disconnect;
            struct work_struct ws_scan, ws_scan_timeout;

            /* For quickly finding the AP */
            struct vcd_vi *ap;
        };
        /* Structure for AP mode */
        struct {
            /* List node for storing AP (vcd->ap_list is the head),
             * this field is for interface in AP mode.
             */
            struct list_head ap_list;
        };
    };
};

static int station = 2;
module_param(station, int, 0444);
MODULE_PARM_DESC(station, "Number of virtual interfaces running in STA mode.");

/* Global context */
static struct vcd_context *vcd = NULL;

/* helper function to retrieve vi(virtual interface) from net_device */
static inline struct vcd_vi *ndev_get_vcd_vi(struct net_device *ndev)
{
    return (struct vcd_vi *) netdev_priv(ndev);
}

/* This is not a good method.
 * In the future, we can try to make result smoother.*/
static inline s32 random_RSSI(s32 low, s32 up)
{
    s32 result = 0;
	get_random_bytes(&result,sizeof(result));
    result = (result % (up - low + 1)) + low;
    return result;
}

/* This function will prepare structure with self-defined BSS information
 * and "inform" the kernel about "new" BSS.
 */
static void inform_bss(struct vcd_vi *vi)
{
    struct vcd_vi *ap;

    list_for_each_entry (ap, &vcd->ap_list, ap_list) {
        struct cfg80211_bss *bss = NULL;
        struct cfg80211_inform_bss data = {
            /* the only channel */
            .chan = &ap->wdev.wiphy->bands[NL80211_BAND_2GHZ]->channels[0],
            .scan_width = NL80211_BSS_CHAN_WIDTH_20,
            .signal = DBM_TO_MBM(random_RSSI(-100, -30)),
        };

        pr_info("vcd: %s performs scan, found %s (SSID: %s, BSSID: %pM)\n",
                vi->ndev->name, ap->ndev->name, ap->ssid, ap->bssid);
        
        /* Information Element(IE)*/
        u8 *ie = kmalloc(ap->ssid_len + 2, GFP_KERNEL);
        ie[0] = WLAN_EID_SSID;
        ie[1] = ap->ssid_len;
        memcpy(ie + 2, ap->ssid, ap->ssid_len);
        
        u64 tsf = div_u64(ktime_get_boottime_ns(), 1000);

        /* It is posible to use cfg80211_inform_bss() instead. */
        bss = cfg80211_inform_bss_data(
            vi->wdev.wiphy, &data, CFG80211_BSS_FTYPE_UNKNOWN, ap->bssid, tsf,
            WLAN_CAPABILITY_ESS, 100, ie, ap->ssid_len + 2, GFP_KERNEL);

        /* cfg80211_inform_bss_data() returns cfg80211_bss structure referefence
         * counter of which should be decremented if it is unused.
         */
        cfg80211_put_bss(vi->wdev.wiphy, bss);
        kfree(ie);
    }
}

static int vcd_ndo_open(struct net_device *dev)
{
    netif_start_queue(dev);
    return 0;
}

static int vcd_ndo_stop(struct net_device *dev)
{
    struct vcd_vi *vi = ndev_get_vcd_vi(dev);
    struct vcd_packet *pkt, *is = NULL;
    list_for_each_entry_safe (pkt, is, &vi->rx_queue, list) {
        list_del(&pkt->list);
        kfree(pkt);
    }
    netif_stop_queue(dev);
    return 0;
}

static struct net_device_stats *vcd_ndo_get_stats(struct net_device *dev)
{
    struct vcd_vi *vi = ndev_get_vcd_vi(dev);
    return &vi->stats;
}

/* vcd_ndo_start_xmit() transmit packet and vcd_rx() receive packet. 
 * Note that packet transmission and reception have different methods
 * in different "modes"(STA,AP) and "cast"(uni,broad,multi).
 */
static netdev_tx_t vcd_ndo_start_xmit(struct sk_buff *skb,
                                      struct net_device *dev);

/* Receive a packet */
static void vcd_rx(struct net_device *dev)
{
    struct vcd_vi *vi = ndev_get_vcd_vi(dev);
    /* skb: socket buffer will be sended to protocol stack.
     * skb1: socket buffer will be transmitted to another STA.
     */
    struct sk_buff *skb, *skb1 = NULL;
    struct vcd_packet *pkt;

    if (list_empty(&vi->rx_queue)) {
        pr_info("vcd rx: No packet in rx_queue\n");
        return;
    }

    if (mutex_lock_interruptible(&vi->lock))
        goto pkt_free;

    pkt = list_first_entry(&vi->rx_queue, struct vcd_packet, list);

    vi->stats.rx_bytes += pkt->datalen;
    vi->stats.rx_packets++;
    vi->active_time = jiffies;

    mutex_unlock(&vi->lock);

    /* Put raw packet into socket buffer */
    skb = dev_alloc_skb(pkt->datalen + 2);
    if (!skb) {
        pr_info("vcd rx: low on mem - packet dropped\n");
        vi->stats.rx_dropped++;
        goto pkt_free;
    }
    skb_reserve(skb, 2); /* align IP on 16B boundary */
    memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);

    list_del(&pkt->list);
    kfree(pkt);

    if (vi->wdev.iftype == NL80211_IFTYPE_AP) {
        struct ethhdr *eth_hdr = (struct ethhdr *) skb->data;

        /* Receiving a multicast/broadcast packet, send it to every
         * STA except the source STA, and pass it to protocol stack.
         */
        if (is_multicast_ether_addr(eth_hdr->h_dest)) {
            pr_info("vcd: is_multicast_ether_addr\n");
            skb1 = skb_copy(skb, GFP_KERNEL);
        }
        /* Receiving a unicast packet */
        else {
            /* The packet is not for AP itself, send it to destination
             * STA, and do not pass it to procotol stack.
             */
            if (!ether_addr_equal(eth_hdr->h_dest, vi->ndev->dev_addr)) {
                skb1 = skb;
                skb = NULL;
            }
        }

        if (skb1) {
            pr_info("vcd: AP %s relay:\n", vi->ndev->name);
            vcd_ndo_start_xmit(skb1, vi->ndev);
        }

        /* Nothing to pass to protocol stack */
        if (!skb)
            return;
    }

    /* Pass the skb to protocol stack */
    skb->dev = dev;
    skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
    skb->protocol = eth_type_trans(skb, dev);
    netif_rx_ni(skb);

    return;

pkt_free:
    list_del(&pkt->list);
    kfree(pkt);
}

static int __vcd_ndo_start_xmit(struct vcd_vi *vi,
                                struct vcd_vi *dest_vi,
                                struct sk_buff *skb)
{
    struct vcd_packet *pkt = NULL;
    struct ethhdr *eth_hdr = (struct ethhdr *) skb->data;
    int datalen;

    if (vi->wdev.iftype == NL80211_IFTYPE_STATION) {
        pr_info("vcd: STA %s (%pM) send packet to AP %s (%pM)\n",
                vi->ndev->name, eth_hdr->h_source, dest_vi->ndev->name,
                eth_hdr->h_dest);
    } else if (vi->wdev.iftype == NL80211_IFTYPE_AP) {
        pr_info("vcd: AP %s (%pM) send packet to STA %s (%pM)\n",
                vi->ndev->name, eth_hdr->h_source, dest_vi->ndev->name,
                eth_hdr->h_dest);
    }

    pkt = kmalloc(sizeof(struct vcd_packet), GFP_KERNEL);
    if (!pkt) {
        pr_info("Ran out of memory allocating packet pool\n");
        return NETDEV_TX_OK;
    }
    datalen = skb->len;
    memcpy(pkt->data, skb->data, datalen);
    pkt->datalen = datalen;

    /* enqueue packet to destination vi's rx_queue */
    if (mutex_lock_interruptible(&dest_vi->lock))
        goto l_error_before_rx_queue;

    list_add_tail(&pkt->list, &dest_vi->rx_queue);

    mutex_unlock(&dest_vi->lock);

    if (mutex_lock_interruptible(&vi->lock))
        goto l_erorr_after_rx_queue;

    /* Update interface statistics */
    vi->stats.tx_packets++;
    vi->stats.tx_bytes += datalen;
    vi->active_time = jiffies;

    mutex_unlock(&vi->lock);

    if (dest_vi->wdev.iftype == NL80211_IFTYPE_STATION) {
        pr_info("vcd: STA %s (%pM) receive packet from AP %s (%pM)\n",
                dest_vi->ndev->name, eth_hdr->h_dest, vi->ndev->name,
                eth_hdr->h_source);
    } else if (dest_vi->wdev.iftype == NL80211_IFTYPE_AP) {
        pr_info("vcd: AP %s (%pM) receive packet from STA %s (%pM)\n",
                dest_vi->ndev->name, eth_hdr->h_dest, vi->ndev->name,
                eth_hdr->h_source);
    }


    /* Directly send to rx_queue, simulate the rx interrupt */
    vcd_rx(dest_vi->ndev);

    return datalen;

l_erorr_after_rx_queue:
    list_del(&pkt->list);
l_error_before_rx_queue:
    kfree(pkt);
    return 0;
}

/* Network packet transmit */
static netdev_tx_t vcd_ndo_start_xmit(struct sk_buff *skb,
                                      struct net_device *dev)
{
    struct vcd_vi *vi = ndev_get_vcd_vi(dev);
    struct vcd_vi *dest_vi = NULL;
    struct ethhdr *eth_hdr = (struct ethhdr *) skb->data;
    int count = 0;

    /* TX by interface of STA mode */
    if (vi->wdev.iftype == NL80211_IFTYPE_STATION) {
        if (vi->ap) {
            dest_vi = vi->ap;

            if (__vcd_ndo_start_xmit(vi, dest_vi, skb))
                count++;
        }
    }
    /* TX by interface of AP mode */
    else if (vi->wdev.iftype == NL80211_IFTYPE_AP) {
        /* Check if the packet is broadcasting */
        if (is_broadcast_ether_addr(eth_hdr->h_dest)) {
            list_for_each_entry (dest_vi, &vi->bss_list, bss_list) {
                /* Don't send broadcast packet back
                 * to the source interface.
                 */
                if (ether_addr_equal(eth_hdr->h_source,
                                     dest_vi->ndev->dev_addr))
                    continue;

                if (__vcd_ndo_start_xmit(vi, dest_vi, skb))
                    count++;
            }
        }
        /* The packet is unicasting */
        else {
            list_for_each_entry (dest_vi, &vi->bss_list, bss_list) {
                if (ether_addr_equal(eth_hdr->h_dest,
                                     dest_vi->ndev->dev_addr)) {
                    if (__vcd_ndo_start_xmit(vi, dest_vi, skb))
                        count++;
                    break;
                }
            }
        }
    }

    if (!count)
        vi->stats.tx_dropped++;

    /* Don't forget to cleanup skb, as its ownership moved to xmit callback. */
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

/* Structure of functions for network devices. */
static struct net_device_ops vcd_ndev_ops = {
    .ndo_open = vcd_ndo_open,
    .ndo_stop = vcd_ndo_stop,
    .ndo_start_xmit = vcd_ndo_start_xmit,
    .ndo_get_stats = vcd_ndo_get_stats,
};

/* Inform the "dummy" BSS to kernel and call cfg80211_scan_done() to finish
 * scan.
 */
static void vcd_scan_timeout_work(struct work_struct *w)
{
    struct vcd_vi *vi = container_of(w, struct vcd_vi, ws_scan_timeout);
    struct cfg80211_scan_info info = {
        /* if scan was aborted by user (calling cfg80211_ops->abort_scan) or by
         * any driver/hardware issue - field should be set to "true"
         */
        .aborted = false,
    };

    /* inform with dummy BSS */
    inform_bss(vi);

    if (mutex_lock_interruptible(&vi->lock))
        return;

    /* finish scan */
    cfg80211_scan_done(vi->scan_request, &info);

    vi->scan_request = NULL;

    mutex_unlock(&vi->lock);
}

/* This function just schedules the timeout work 
 * when the scan timer timeouts.
 */
static void vcd_scan_timeout(struct timer_list *t)
{
    struct vcd_vi *vi = container_of(t, struct vcd_vi, scan_timeout);

    if (vi->scan_request)
        schedule_work(&vi->ws_scan_timeout);
}

static void vcd_scan_routine(struct work_struct *w)
{
    struct vcd_vi *vi = container_of(w, struct vcd_vi, ws_scan);
    mod_timer(&vi->scan_timeout, jiffies + msecs_to_jiffies(SCAN_TIMEOUT_MS));
}

static void vcd_connect_routine(struct work_struct *w)
{
    struct vcd_vi *vi = container_of(w, struct vcd_vi, ws_connect);
    struct vcd_vi *ap = NULL;

    if (mutex_lock_interruptible(&vi->lock))
        return;

    /* Finding the AP by request SSID */
    list_for_each_entry (ap, &vcd->ap_list, ap_list) {
        if (!memcmp(ap->ssid, vi->req_ssid, ap->ssid_len)) {
            pr_info("vcd: %s is connected to AP %s (SSID: %s, BSSID: %pM)\n",
                    vi->ndev->name, ap->ndev->name, ap->ssid, ap->bssid);

            cfg80211_connect_result(vi->ndev, NULL, NULL, 0, NULL, 0,
                                    WLAN_STATUS_SUCCESS, GFP_KERNEL);
            memcpy(vi->ssid, ap->ssid, ap->ssid_len);
            memcpy(vi->bssid, ap->bssid, ETH_ALEN);
            vi->sme_state = SME_CONNECTED;
            vi->conn_time = jiffies;
            vi->ap = ap;

            if (mutex_lock_interruptible(&ap->lock))
                return;

            /* Add STA to bss_list, and the head is AP */
            list_add_tail(&vi->bss_list, &ap->bss_list);
            mutex_unlock(&ap->lock);

            mutex_unlock(&vi->lock);

            return;
        }
    }

    /* SSID not found */
    pr_info("vcd: SSID %s not found\n", vi->req_ssid);

    cfg80211_connect_timeout(vi->ndev, NULL, NULL, 0, GFP_KERNEL,
                             NL80211_TIMEOUT_SCAN);
    vi->sme_state = SME_DISCONNECTED;
    mutex_unlock(&vi->lock);
}

/* Invoke cfg80211_disconnected() that informs the kernel that disconnect is
 * complete.
 */
static void vcd_disconnect_routine(struct work_struct *w)
{
    struct vcd_vi *vi = container_of(w, struct vcd_vi, ws_disconnect);

    pr_info("vcd: %s disconnected from AP %s\n", vi->ndev->name,
            vi->ap->ndev->name);

    if (mutex_lock_interruptible(&vi->lock))
        return;

    cfg80211_disconnected(vi->ndev, vi->disconnect_reason_code, NULL, 0, true,
                          GFP_KERNEL);
    vi->disconnect_reason_code = 0;
    vi->sme_state = SME_DISCONNECTED;

    if (vcd->state != vcd_SHUTDOWN) {
        if (mutex_lock_interruptible(&vi->ap->lock)) {
            mutex_unlock(&vi->lock);
            return;
        }

        list_del(&vi->bss_list);
        mutex_unlock(&vi->ap->lock);

        vi->ap = NULL;
    }

    mutex_unlock(&vi->lock);
}

/* This callback should initiate scan routine(through work_struct)
 * and exit with 0 if everything is ok when user decided to scan.
 */
static int vcd_scan(struct wiphy *wiphy, struct cfg80211_scan_request *request)
{
    /* retrieve vi from wireless_dev */
    struct vcd_vi *vi = container_of(request->wdev, struct vcd_vi, wdev);

    if (mutex_lock_interruptible(&vi->lock))
        return -ERESTARTSYS;

    if (vi->scan_request) {
        mutex_unlock(&vi->lock);
        return -EBUSY;
    }

    if (vi->wdev.iftype == NL80211_IFTYPE_AP) {
        mutex_unlock(&vi->lock);
        return -EPERM;
    }
    vi->scan_request = request;

    mutex_unlock(&vi->lock);

    if (!schedule_work(&vi->ws_scan))
        return -EBUSY;
    return 0;
}

/* It initializes connection routine through work_struct and exits with 0
 * if everything is ok when there is need to "connect" to some network.
 */
static int vcd_connect(struct wiphy *wiphy,
                       struct net_device *dev,
                       struct cfg80211_connect_params *sme)
{
    struct vcd_vi *vi = ndev_get_vcd_vi(dev);

    if (mutex_lock_interruptible(&vi->lock))
        return -ERESTARTSYS;

    if (vi->sme_state != SME_DISCONNECTED) {
        mutex_unlock(&vi->lock);
        return -EBUSY;
    }

    if (vi->wdev.iftype == NL80211_IFTYPE_AP) {
        mutex_unlock(&vi->lock);
        return -EPERM;
    }

    vi->sme_state = SME_CONNECTING;
    vi->ssid_len = sme->ssid_len;
    memcpy(vi->req_ssid, sme->ssid, sme->ssid_len);
    mutex_unlock(&vi->lock);

    if (!schedule_work(&vi->ws_connect))
        return -EBUSY;
    return 0;
}

/* It initializes disconnect routine through work_struct and exits with 0 
 * if everything ok when there is need to "diconnect" from  currently 
 * connected network. 
 */
static int vcd_disconnect(struct wiphy *wiphy,
                          struct net_device *dev,
                          u16 reason_code)
{
    struct vcd_vi *vi = ndev_get_vcd_vi(dev);

    if (mutex_lock_interruptible(&vi->lock))
        return -ERESTARTSYS;

    if (vi->sme_state == SME_DISCONNECTED) {
        mutex_unlock(&vi->lock);
        return -EINVAL;
    }

    if (vi->wdev.iftype == NL80211_IFTYPE_AP) {
        mutex_unlock(&vi->lock);
        return -EPERM;
    }

    vi->disconnect_reason_code = reason_code;

    mutex_unlock(&vi->lock);

    if (!schedule_work(&vi->ws_disconnect))
        return -EBUSY;

    return 0;
}

/* When user decided to get informations(numbers and bytes of tx/rx, signal.
 * and timing informations) of a specific station,user can call this function.
 */
static int vcd_get_station(struct wiphy *wiphy,
                           struct net_device *dev,
                           const u8 *mac,
                           struct station_info *sinfo)
{
    struct vcd_vi *vi = ndev_get_vcd_vi(dev);

    if (memcmp(mac, vi->bssid, ETH_ALEN))
        return -ENONET;

    sinfo->filled = BIT_ULL(NL80211_STA_INFO_TX_PACKETS) |
                    BIT_ULL(NL80211_STA_INFO_RX_PACKETS) |
                    BIT_ULL(NL80211_STA_INFO_TX_FAILED) |
                    BIT_ULL(NL80211_STA_INFO_TX_BYTES) |
                    BIT_ULL(NL80211_STA_INFO_RX_BYTES) |
                    BIT_ULL(NL80211_STA_INFO_SIGNAL) |
                    BIT_ULL(NL80211_STA_INFO_INACTIVE_TIME);

    if (vi->sme_state == SME_CONNECTED) {
        sinfo->filled |= BIT_ULL(NL80211_STA_INFO_CONNECTED_TIME);
        sinfo->connected_time =
            jiffies_to_msecs(jiffies - vi->conn_time) / 1000;
    }

    sinfo->tx_packets = vi->stats.tx_packets;
    sinfo->tx_failed = vi->stats.tx_dropped;
    sinfo->tx_bytes = vi->stats.tx_bytes;
    sinfo->rx_packets = vi->stats.rx_packets;
    sinfo->rx_bytes = vi->stats.rx_bytes;
    /* For CFG80211_SIGNAL_TYPE_MBM, value is expressed in dBm */
    sinfo->signal = random_RSSI(-100, -30);
    sinfo->inactive_time = jiffies_to_msecs(jiffies - vi->active_time);
    /* TODO: Emulate rate and mcs */

    return 0;
}

/* Create a virtual interface */
static struct wireless_dev *vcd_interface_add(struct wiphy *wiphy, int if_idx)
{
    struct net_device *ndev = NULL;
    struct vcd_vi *vi = NULL;

    /* allocate network device context. */
    ndev = alloc_netdev(sizeof(struct vcd_vi), NDEV_NAME, NET_NAME_ENUM,
                        ether_setup);

    if (!ndev)
        goto l_error_alloc_ndev;

    /* fill private data of network context. */
    vi = ndev_get_vcd_vi(ndev);
    vi->ndev = ndev;

    /* fill wireless_dev context. */
    vi->wdev.wiphy = wiphy;
    vi->wdev.netdev = ndev;
    vi->wdev.iftype = NL80211_IFTYPE_STATION;
    vi->ndev->ieee80211_ptr = &vi->wdev;

    /* set network device hooks. should implement ndo_start_xmit() at least */
    vi->ndev->netdev_ops = &vcd_ndev_ops;

    /* Add here proper net_device initialization */
    vi->ndev->features |= NETIF_F_HW_CSUM;

    /* The first byte is '\0' to avoid being a multicast
     * address (the first byte of multicast addrs is odd).
     */
    char intf_name[ETH_ALEN] = {0};
    snprintf(intf_name + 1, ETH_ALEN, "%s%d", NAME_PREFIX, if_idx);
    memcpy(vi->ndev->dev_addr, intf_name, ETH_ALEN);

    if (register_netdev(vi->ndev))
        goto l_error_ndev_register;

    /* Initialize connection information */
    memset(vi->bssid, 0, ETH_ALEN);
    memset(vi->ssid, 0, IEEE80211_MAX_SSID_LEN);
    memset(vi->req_ssid, 0, IEEE80211_MAX_SSID_LEN);
    vi->scan_request = NULL;
    vi->sme_state = SME_DISCONNECTED;
    vi->conn_time = 0;
    vi->active_time = 0;
    vi->disconnect_reason_code = 0;
    vi->ap = NULL;

    mutex_init(&vi->lock);

    /* Initialize timer of scan_timeout */
    timer_setup(&vi->scan_timeout, vcd_scan_timeout, 0);

    INIT_WORK(&vi->ws_connect, vcd_connect_routine);
    INIT_WORK(&vi->ws_disconnect, vcd_disconnect_routine);
    INIT_WORK(&vi->ws_scan, vcd_scan_routine);
    INIT_WORK(&vi->ws_scan_timeout, vcd_scan_timeout_work);

    /* Initialize rx_queue */
    INIT_LIST_HEAD(&vi->rx_queue);

    /* Add vi into global vi_list */
    if (mutex_lock_interruptible(&vcd->lock))
        goto l_error_add_list;
    list_add_tail(&vi->list, &vcd->vi_list);
    mutex_unlock(&vcd->lock);

    return &vi->wdev;

l_error_add_list:
    unregister_netdev(vi->ndev);
l_error_ndev_register:
    free_netdev(vi->ndev);
l_error_alloc_ndev:
    wiphy_unregister(wiphy);
    wiphy_free(wiphy);
    return NULL;
}

/* Called by kernel when user decided to change the interface type. */
static int vcd_change_iface(struct wiphy *wiphy,
                            struct net_device *ndev,
                            enum nl80211_iftype type,
                            struct vi_params *params)
{
    switch (type) {
    case NL80211_IFTYPE_STATION:
    case NL80211_IFTYPE_AP:
        ndev->ieee80211_ptr->iftype = type;
        break;
    default:
        pr_info("vcd: invalid interface type %u\n", type);
        return -EINVAL;
    }

    return 0;
}

/* Called by the kernel when user want to create an Access Point. Now
 * it just add a ssid to the ssid_table to emulate the AP signal. And
 * record the ssid to the vcd_context.
 */
static int vcd_start_ap(struct wiphy *wiphy,
                        struct net_device *ndev,
                        struct cfg80211_ap_settings *settings)
{
    struct vcd_vi *vi = ndev_get_vcd_vi(ndev);

    pr_info("vcd: %s start acting in AP mode.\n", ndev->name);
    pr_info("ctrlchn=%d, center=%d, bw=%d, beacon_interval=%d, dtim_period=%d,",
            settings->chandef.chan->hw_value, settings->chandef.center_freq1,
            settings->chandef.width, settings->beacon_interval,
            settings->dtim_period);
    pr_info("ssid=%s(%zu), auth_type=%d, inactivity_timeout=%d", settings->ssid,
            settings->ssid_len, settings->auth_type,
            settings->inactivity_timeout);

    if (settings->ssid == NULL)
        return -EINVAL;

    /* Seting up AP SSID and BSSID */
    vi->ssid_len = settings->ssid_len;
    memcpy(vi->ssid, settings->ssid, settings->ssid_len);
    memcpy(vi->bssid, vi->ndev->dev_addr, ETH_ALEN);

    /* AP is the head of vi->bss_list */
    INIT_LIST_HEAD(&vi->bss_list);

    /* Add AP to global ap_list */
    list_add_tail(&vi->ap_list, &vcd->ap_list);

    return 0;
}

/* Structure of functions for FullMAC 80211 drivers. */
static struct cfg80211_ops vcd_cfg_ops = {
    .change_virtual_intf = vcd_change_iface,
    .scan = vcd_scan,
    .connect = vcd_connect,
    .disconnect = vcd_disconnect,
    .get_station = vcd_get_station,
    .start_ap = vcd_start_ap,
    .stop_ap = vcd_stop_ap, // in the future
};

/* Array of "supported" channels in 2GHz band. It is required for wiphy.
 * For demo - the only channel 6.
 */
static struct ieee80211_channel vcd_supported_channels_2ghz[] = {
    {
        .band = NL80211_BAND_2GHZ,
        .hw_value = 6,
        .center_freq = 2437,
    },
};

/* Array of supported rates, required to support at least those next rates
 * for 2GHz band.
 */
static struct ieee80211_rate vcd_supported_rates_2ghz[] = {
    {
        .bitrate = 10,
        .hw_value = 0x1,
    },
    {
        .bitrate = 20,
        .hw_value = 0x2,
    },
    {
        .bitrate = 55,
        .hw_value = 0x4,
    },
    {
        .bitrate = 110,
        .hw_value = 0x8,
    },
};

/* Describes supported band of 2GHz. */
static struct ieee80211_supported_band nf_band_2ghz = {
    /* FIXME: add other band capabilities if nedded, such as 40 width */
    .ht_cap.cap = IEEE80211_HT_CAP_SGI_20,
    .ht_cap.ht_supported = false,

    .channels = vcd_supported_channels_2ghz,
    .n_channels = ARRAY_SIZE(vcd_supported_channels_2ghz),

    .bitrates = vcd_supported_rates_2ghz,
    .n_bitrates = ARRAY_SIZE(vcd_supported_rates_2ghz),
};

/* Unregister and free virtual interfaces and wiphy. */
static void vcd_free(void)
{
    struct vcd_vi *vi = NULL, *safe = NULL;

    list_for_each_entry_safe (vi, safe, &vcd->vi_list, list)
        vcd_delete_interface(vi); // in the future

    kfree(vcd);
}

/* Allocate and register wiphy. */
static struct wiphy *vcd_cfg80211_add(void)
{
    struct wiphy *wiphy = NULL;

    /* allocate wiphy context. */
    wiphy = wiphy_new_nm(&vcd_cfg_ops, 0, NULL);
    if (!wiphy) {
        pr_info("couldn't allocate wiphy device\n");
        return NULL;
    }

    /* wiphy should determinate its type. */
    wiphy->interface_modes =
        BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP);

    /* wiphy should have at least 1 band.
     * Also fill NL80211_BAND_5GHZ if required. In this module, only 1 band
     * with 1 "channel"
     */
    wiphy->bands[NL80211_BAND_2GHZ] = &nf_band_2ghz;

    /* scan - if the device supports "scan", we need to define max_scan_ssids
     * at least.
     */
    wiphy->max_scan_ssids = MAX_PROBED_SSIDS;

    /* Signal type
     * CFG80211_SIGNAL_TYPE_UNSPEC allows us specify signal strength from 0 to
     * 100. The reasonable value for CFG80211_SIGNAL_TYPE_MBM is -3000 to -10000
     * (mdBm).
     */
    wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;

    wiphy->flags |= WIPHY_FLAG_NETNS_OK;

    /* zegister wiphy, if everything ok - there should be another wireless
     * device in system. use command: $ iw list
     * Wiphy vcd
     */
    if (wiphy_register(wiphy) < 0) {
        pr_info("couldn't register wiphy device\n");
        goto l_error_wiphy_register;
    }

    return wiphy;

l_error_wiphy_register:
    wiphy_free(wiphy);
    return NULL;
}

static int __init vwifi_init(void)
{
    vcd = kmalloc(sizeof(struct vcd_context), GFP_KERNEL);
    if (!vcd) {
        pr_info("couldn't allocate space for vcd_context\n");
        return -ENOMEM;
    }

    mutex_init(&vcd->lock);
    INIT_LIST_HEAD(&vcd->vi_list);
    INIT_LIST_HEAD(&vcd->ap_list);

    for (int i = 0; i < station; i++) {
        struct wiphy *wiphy = vcd_cfg80211_add();
        if (!wiphy)
            goto l_cfg80211_add;
        if (!vcd_interface_add(wiphy, i))
            goto l_interface_add;
    }

    vcd->state = vcd_READY;

    return 0;

l_interface_add:
l_cfg80211_add:
    vcd_free();
    return -1;
}

static void __exit vwifi_exit(void)
{
    vcd->state = vcd_SHUTDOWN;
    vcd_free(); // not finished
}

module_init(vwifi_init);
module_exit(vwifi_exit);