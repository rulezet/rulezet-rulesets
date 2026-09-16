rule pony {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-08-16"
        description = "Identify Pony"
	strings:
    	$s1 = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
    	$s2 = "YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0"
    	$s3 = "POST %s HTTP/1.0"
    	$s4 = "Accept-Encoding: identity, *;q=0"

    	    	    condition:
        $s1 and $s2 and $s3 and $s4
}