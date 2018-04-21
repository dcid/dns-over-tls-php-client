# dnstls
DNS over TLS PHP Client

This is a proof of concept for DNS over TLS in PHP. It is based on the latest draft `https://tools.ietf.org/html/rfc7858` and was tested against the DNSDist and Knot TLS servers. Should work with all implementations. This is a work in progress and only the A, AAAA and CNAME records are supported. 

MX and NS are coming soon.

It supports CloudFlare's , Quad9's and CleanBrowsing public DNS servers by default.


## Examples

This tool should be executed from the command line and it has a similar output as the `host` command. Example:

     $ php dnstls.php 
     Usage: dnstls.php [domain.com] [server:cloudflare,cleanbrowsing,IP] <type: A, AAAA or CNAME>


     $php dnstls.php github.com cloudflare
     github.com has address 192.30.255.113
     github.com has address 192.30.255.112

Or for IPv6:

     $ php dnstls.php sucuri.net quad9 AAAA
     sucuri.net has IPv6 address 2a02:fe80:1010::16

If you are using CleanBrowsing, it will block (return not found) for adult sites:

     $ php dnstls.php pornhub.com cleanbrowsing 
     Host pornhub.com not found: 3(NXDOMAIN)



## Limitations

This is just an initial test version. Use at your own risk. PRs are always welcome.
