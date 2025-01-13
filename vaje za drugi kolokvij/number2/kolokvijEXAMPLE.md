

# An Example Midterm 2

## System Administration Assignment

Your task is to install server (@hq) at A.C.M.E. cooperation headquarters (in Ljubljana) and client (@br) at an A.C.M.E. branch (remote location) to enable secure access to classified documents.

### Virtual Private Network
    - Create the main virtual machine and install necessary packages. 

0. **Disable IPv6**

    Start the image and login as isp/isp.

    ```sh
    sudo nano /etc/sysctl.conf
    ```

    Add the following lines at the end of the file:
    ```sh
    net.ipv6.conf.all.disable_ipv6 = 1
    net.ipv6.conf.default.disable_ipv6 = 1
    net.ipv6.conf.lo.disable_ipv6 = 1
    ```

    Activate changes by running:
    ```sh
    sudo sysctl -p
    ```

    To verify that IPv6 has been disabled, run:
    ```sh
    cat /proc/sys/net/ipv6/conf/all/disable_ipv6
    ```
    This should output `1`.

1. **Network:**
    - Create a new NAT in VirtualBox -> tools -> network -> NAT Networks named `nat_midterm`
    - On the HQ_SERVER VM, set the first adapter to NAT Network `nat_midterm` 
    - On BR_CLIENT VM, set the first adapter to NAT Network  `nat_midterm`


2. **Network Configuration**


    
    - **HQ Server (@hq):**
        - VPN Network: `10.1.0.0/16`
        - Private Address: `10.1.0.1`
    
    - **Branch Client (@br):**
        - VPN Network: `10.2.0.0/16`
        - Private Address: `10.2.0.1`
    
    - **StrongSwan Installation on Both @hq and @br:**
        ```sh
        sudo apt-get update
        sudo apt-get install strongswan

        sudo apt-get install strongswan-pki libcharon-extra-plugins apache2 wireshark net-tools
        ```

        say```yes```
    
        ```
        # HQ_SERVER /etc/ipsec.conf
        config setup
        
        conn %default 
            ikelifetime=60m keylife=20m rekeymargin=3m keyingtries=1 keyexchange=ikev2
        authby=secretconn net-net leftsubnet=10.1.0.0/16 leftfirewall=
        yes
        leftid=@hq right= 10.2.0.1
        rightsubnet=10.2.0.0/16 rightid=@branch auto=add
        ```

        ```
        # HQ_SERVER /etc/ipsec.secrets
        @hq @branch : PSK "this_is_my_psk;"
        ```
        ssh ukaz iz 
        ```
        # BR_CLIENT  /etc/ipsec.conf
        config setupconn %default ikelifetime=60m keylife=20m rekeymargin=3m keyingtries=1 keyexchange=ikev2 authby=secretconn net-net leftsubnet=10.2.0.0/16 leftid=@branch leftfirewall=
        yes
        right=10.1.0.1
        rightsubnet=10.1.0.0/16 rightid=@hq auto=add
        ```

        ```
        # BR_CLIENT /etc/ipsec.secrets
        @hq @branch : PSK "this_is_my_psk;"
        ```

        ```
        sudo ipsec restart
        sudo ipsec status[all]
        sudo ipsec up net-net
        ```
   
    
    - **Apply Configuration:**
        ```sh
        sudo systemctl restart strongswan
        sudo systemctl enable strongswan
        ```
    
    - **Verify VPN Connection:**
        ```sh
        ipsec status
        ping 10.2.0.1
        ```
 
    četrtek 10-12
    - **HQ Server Configuration**
    1. Start `hq_server`
    2. Edit network configuration:
        `/etc/netplan/01-network-manager-all.yaml`
        ```yaml
        network:
          version: 2
          ethernets:
            enp0s3:
              addresses: [10.1.0.1/16]
              routes:
                - to: default
                  via: 10.1.0.1
              nameservers:
                addresses: [8.8.8.8]
        ```
    3. Apply changes:
        ```sh
        sudo netplan apply
        ```

5. **Setting Up the Branch**

    **Branch Router Configuration**
    1. Start `branch_router`
    2. Edit network configuration:
        `/etc/netplan/01-network-manager-all.yaml`
        ```yaml
        network:
          version: 2
          ethernets:
            enp0s3:
              dhcp4: true
              dhcp-identifier: mac
            enp0s8:
              addresses: [10.2.0.1/16]
        ```
    3. Apply changes:
        ```sh
        sudo netplan apply
        ```
    4. Enable packet forwarding:
        ```sh
        echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
        ```


1. **Install StrongSwan on both @hq and @br machines:**
    ```sh
    sudo apt-get update
    sudo apt-get install strongswan strongswan-pki libcharon-extra-plugins apache2 wireshark net-tools
    ```
2. **Configure IPsec and ISAKMP with pre-shared key authentication (PSK):**
    - Edit `/etc/ipsec.conf`:
        ```conf
        config setup
          charondebug="all"
        
        conn %default
          keyexchange=ikev2
          ike=aes256-sha256-modp1024
          esp=aes256-sha256
          dpdaction=clear
          dpddelay=300s
          dpdtimeout=1h
        
        conn vpn
          left=10.1.0.1
          leftsubnet=10.1.0.0/16
          right=10.2.0.1
          rightsubnet=10.2.0.0/16
          authby=secret
          auto=add
        ```
    - Edit `/etc/ipsec.secrets`:
        ```
        10.1.0.1 10.2.0.1 : PSK "this_is_my_psk"
        ```
3. **Apply the configuration:**
    ```sh
    sudo ipsec restart
    ```

### Secure Shell

1. **Install SSH server on the @hq machine:**
    ```sh
    sudo apt-get install openssh-server
    ```
2. **Verify SSH access from @br to @hq:**
    ```sh
    ssh user@10.1.0.1
    ```
3. **Generate an ECDSA keypair on @br:**
    ```sh
    ssh-keygen -t ecdsa
    ```
4. **Copy the public key to @hq:**
    ```sh
    ssh-copy-id -i ~/.ssh/id_ecdsa.pub user@10.1.0.1
    ```
5. **Modify the SSH configuration on @hq to allow only public-key authentication:**
    - Edit `/etc/ssh/sshd_config`:
        ```conf
        PasswordAuthentication no
        PubkeyAuthentication yes
        ```
    - Restart SSH service:
        ```sh
        sudo systemctl restart ssh
        ```

### Firewall Rules

1. **Set up iptables firewall on @hq:**
    ```sh
    sudo apt-get install iptables
    ```
2. **Permit VPN, SSH, and ICMP traffic, block others:**
    ```sh
    sudo iptables -A INPUT -p udp --dport 500 -j ACCEPT
    sudo iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    sudo iptables -A INPUT -p ah -j ACCEPT
    sudo iptables -A INPUT -p esp -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    sudo iptables -A INPUT -p icmp -j ACCEPT
    sudo iptables -P INPUT DROP
    ```
3. **Save iptables rules:**
    ```sh
    sudo iptables-save | sudo tee /etc/iptables/rules.v4
    ```

**Note:** You are not required to set up a firewall on the @br computer.