rule Careto_CnC_domains 
{

    meta:
        author = "AlienVault (Alberto Ortega)"
        description = "TheMask / Careto known command and control domains"
        reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"
        date = "2014/02/11"

    strings:
        $1 = "linkconf.net" ascii wide nocase
        $2 = "redirserver.net" ascii wide nocase
        $3 = "swupdt.com" ascii wide nocase

    condition:
        any of them
}