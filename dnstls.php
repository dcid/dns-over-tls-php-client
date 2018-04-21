<?php

/* PHP client implementation for DNS over TLS.
 * Based on: https://tools.ietf.org/html/rfc7858
 * Supports A, AAAA and CNAME records.
 * Author: dcid
 * License: GPLv3
 */


/* Public DNS over TLS servers:
 * cloudflare: 1.1.1.1
 * quad9: 9.9.9.9  (blocking malicious domains)
 * cleanbrowsing: 185.228.168.168 (blocking adult content)
 */



/* Domain str to DNS raw qname */
function dnslib_domain2raw($domainname)
{
    $raw = "";
    $domainpieces = explode('.', $domainname);
    foreach($domainpieces as $domainbit)
    {
        $raw = $raw.chr(strlen($domainbit)).$domainbit;
    }
    $raw = $raw.chr(0);
    return($raw);
}


/* DNS raw qname to domain str */
function dnslib_raw2domain($qname)
{
    $mylenght = ord($qname[0]);
    $domainname = "";
    $i = 1;
    while(1)
    {
        while($mylenght)
        {
            $domainname = $domainname.$qname[$i++];
            $mylenght--;
        }
        $mylenght = ord($qname[$i]);
        $i++;

        if($mylenght == 0)
        {
            break;
        }
        else if($mylenght == 192)
        {
            /* cname pointing to itself */
            break;
        }
        $domainname = $domainname.".";
    }
    return($domainname);
}


/* DNS type names to raw types */
function dnslib_get_qtypes($requesttype = "A")
{
    if($requesttype === "AAAA")
    {   
        $rawtype = 28;
    }
    else if($requesttype === "CNAME")
    {   
        $rawtype = 5;
    }
    else if($requesttype === "NS")
    {   
        $rawtype = 2;
    }
    else
    {   
        $rawtype = 1;
    }
    return($rawtype);
}


/* Generate a DNS raw query */
function dnslib_generate_dnsquery($domainname, $requesttype="A")
{
    /* todo: add random id */
    $rawtype = dnslib_get_qtypes($requesttype);
    $dns_query  = sprintf("\xab\xcd").chr(1).chr(0).
                  chr(0).chr(1).  /* qdc */
                  chr(0).chr(0).  /* anc */
                  chr(0).chr(0).  /* nsc */
                  chr(0).chr(0).  /* arc */
                  dnslib_domain2raw($domainname). 
                  chr(0).chr($rawtype). 
                  chr(0).chr(1);  /* qclass */
    return($dns_query);
}


/* Parses DNS raw answers. */
function dnslib_read_dnsanswer($raw, $requesttype)
{
    $results = array();
    $raw_counter = 0;

    $rawtype = dnslib_get_qtypes($requesttype);

    /* Getting header. */
    $qst_header = unpack("nid/nspec/nqdcount/nancount/nnscount/narcount", substr($raw, $raw_counter, 12));
    $raw_counter += 12;

    if($qst_header['ancount'] == 0)
    {
        return($results);
    }

    $domainresp = dnslib_raw2domain(substr( $raw, $raw_counter));


    $raw_counter += strlen($domainresp) + 2;
    $rawtype = ord($raw[$raw_counter + 7]);


    $ans_header = unpack("ntype/nclass/Nttl/nlength", substr( $raw, $raw_counter, 10 ) );
    $raw_counter += 13;

    /* Jumping to the IP address */
    $raw_counter += 3;

    $iplength = 4;
    if($rawtype === 28)
    {
        $iplength = 16;
    }

    if($rawtype == 1 || $rawtype == 28)
    {
        $result_ip = inet_ntop(substr( $raw, $raw_counter, $iplength ));
        if($rawtype == 1)
        {
            $results['ipv4'][] = $result_ip;
        }
        else
        {
            $results['ipv6'][] = $result_ip;
        }
        
        /* Looping through all answers */
        if($qst_header['ancount'] > 1)
        {
            $i = 1;
            while($i < $qst_header['ancount'])
            {
                $raw_counter += $iplength;
                $raw_counter += 12;
                if($rawtype == 1)
                {
                    $results['ipv4'][] = inet_ntop(substr( $raw, $raw_counter , $iplength ));
                }
                else
                {
                    $results['ipv6'][] = $result_ip;
                }
                $i++;
            }
        }
    }
    else if($rawtype == 5)
    {
        $domainresp = dnslib_raw2domain(substr( $raw, $raw_counter));
        $results['cname'][] = $domainresp;
    }
    return($results);
}



/* Testing. */
if(!isset($argv[2]))
{
    echo "Usage: ". $argv[0]. " [domain.com] [server:cloudflare,cleanbrowsing,IP] <type: A, AAAA or CNAME>\n";
    exit(1);
}

$domainname = $argv[1];
if(!isset($argv[3]))
{
    $requesttype = "A";
}
else
{
    $requesttype = $argv[3];
}



$dnsserver = "1.1.1.1";
$peer_name = "1.1.1.1";
if($argv[2] == "cloudflare")
{
    $dnsserver = "1.1.1.1";
}
else if($argv[2] == "quad9")
{
    $dnsserver = "9.9.9.9";
    $peer_name = "dns.quad9.net";
}
else if($argv[2] == "cleanbrowsing")
{
    $dnsserver = "185.228.168.168";
    $peer_name = "cleanbrowsing.org";
}
else
{
    $peer_name = $dnsserver = $argv[2];
    	 
}

$dnsquery = dnslib_generate_dnsquery($domainname, $requesttype);


$context = stream_context_create();
stream_context_set_option($context, 'ssl', 'verify_host', true);
stream_context_set_option($context, 'ssl', 'verify_peer_name', true);
stream_context_set_option($context, 'ssl', 'SNI_server_name', $peer_name);
stream_context_set_option($context, 'ssl', 'peer_name', $peer_name);


/* Connecting to TLS */
$socket = stream_socket_client("ssl://$dnsserver:853", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $context);
if($socket == FALSE)
{
    echo "error: $errstr ($errno)\n";
    exit(1);
}
stream_set_timeout($socket, 5);


/* For TCP, we need to add the length */
$dnsquery = pack("n", strlen($dnsquery)).$dnsquery;
fwrite($socket, $dnsquery);

if(!$responselength = fread($socket, 2))
{
    echo "error: read timeout reading from $dnsserver\n";
    fclose($socket);
    exit(1);
}


/* Getting response size. */
$unpackedresp = unpack("nsize", $responselength);
$sizetoread = $unpackedresp['size'];
$dnsrawresults = fread($socket, $sizetoread);

$dnsresults = dnslib_read_dnsanswer($dnsrawresults, $requesttype);

fclose($socket);

if(empty($dnsresults))
{
    echo "Host $domainname not found: 3(NXDOMAIN)\n";
    exit(1);
}

if(isset($dnsresults['ipv4']))
{
    foreach($dnsresults['ipv4'] as $ipv4)
    {
        echo "$domainname has address $ipv4\n";
    }
}
if(isset($dnsresults['ipv6']))
{
    foreach($dnsresults['ipv6'] as $ipv6)
    {
        echo "$domainname has IPv6 address $ipv6\n";
    }
}
if(isset($dnsresults['cname']))
{
    foreach($dnsresults['cname'] as $cname)
    {
        echo "$domainname is an alias for $cname.\n";
    }
}



exit(0);
