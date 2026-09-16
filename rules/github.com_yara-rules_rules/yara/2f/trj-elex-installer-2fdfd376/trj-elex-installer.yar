rule Trj_Elex_Installer 
{

    meta:
        author = "Centro Criptológico Nacional (CCN)"
        description = "Elex Installer"
        ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
        
    strings:
        $mz = { 4d 5a }
        $str1 = {65 00 76 00 65 00 72 00 79 00 74 00 68 00 69 00 6e 00 67 00}
        $str2 = "IsWow64Process"
        $str3 = "SSFK"
        
    condition:
        ($mz at 0) and ($str1) and ($str2) and ($str3)
}