rule Zlib_Backdoor
{
   
    meta:
        author = "Cylance SPEAR Team"
        
        


    strings:
        $auth = {C6 45 D8 50 C6 45 D9 72 C6 45 DA 6F C6 45 DB 78 C6 45 DC 79 C6 45 DD 2D}
        $auth2 = {C7 45 FC 00 04 00 00 C6 45 ?? 50 C6 45 ?? 72 C6 45 ?? 6F}
        $ntlm = "NTLM" wide
    
    condition:
        ($auth or $auth2) and $ntlm
}