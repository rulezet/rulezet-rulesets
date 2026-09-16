rule glassrat: RAT
{
   meta:
        author = "Brian Wallace @botnet_hunter"
   strings:
    	$a = "PostQuitMessage"
        $b = "pwlfnn10,gzg"
        $c = "update.dll"
        $d = "_winver"
   condition:
    	all of them

}