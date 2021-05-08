Cách dùng khá đơn giản
Có 2 Trường hợp xảy ra
 - Mở port cho vm này kết nối vm khác
 - Mở port public ra ngoài để tất cả kết nối vô

Trước hết xác định rõ giúp em như sau:
 - VM cần mở port
   * VM port sẽ mở trên đó.
        VD: VM 3cx-idb-01 port 5432 sẽ mở trên đó
   * VM sẽ kết nối port của VM trên
        VD: VM app-idb-02 sẽ kết nối tới port 5432 của 3cx-idb-01
   * Trong trường hợp mở port public chưa xác định được tên VM sẽ kết nối vô thì mình để trống ""
 - Port sẽ mở ở VM đó
 - Protocol 

Sau khi xác định được các yêu tố trên, ở phần main sẽ có hàm add add_firewall_vm(ip, idmaymo, idmayketnoi, portmaycanmo, protocol)

VD: add_firewall_vm(ip_proxmox,"ec2-3cx-idb-10-200-100-146-idb-com-vn","ec2-sbc-idb-10-200-100-144-idb-com-vn","5432","tcp")
    add_firewall_vm(ip_proxmox,"ec2-3cx-idb-10-200-100-146-idb-com-vn","","8080","tcp")

Ngoài ra nếu như không biết chính xác tên của vm đó, em có hàm find_vm(ip, vm_name) để tìm tên chính xác vm cần mở port 
    VD: find_vm("10.200.104.3","idb") 
    -> [{'id': 115,
        'name-vm': 'vpc-cmc-hcm-2.idb.com.vn-115',
        'node-name': 'ceph-mon-10-200-104-24-vnpt-tanthuan-bg33-23'},
        {'id': 184,
        'name-vm': 'ec2-vyos-web-idb-wan-103-146-20-3-4-5-lan-10-200-100-9-isws-io',
        'node-name': 'compute-10-200-104-22-vnpt-tanthuan-bg32-22'},
        {'id': 266,
        'name-vm': 'ec2-radius-vpn-10-200-101-20-idb-com-vn',
        'node-name': 'compute-10-200-104-21-vnpt-tanthuan-bg32-33'},
        {'id': 289,
        'name-vm': 'ec2-3cx-idb-10-200-100-146-idb-com-vn',
        'node-name': 'compute-10-200-104-15-vnpt-tanthuan-bg32-28'},
        {'id': 317,
        'name-vm': 'ec2-sbc-idb-10-200-100-144-idb-com-vn',
        'node-name': 'compute-10-200-104-15-vnpt-tanthuan-bg32-28'}]
