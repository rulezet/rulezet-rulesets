rule ce_enfal_cmstar_debug_msg
{
    meta:
        Author      = "rfalcone"
        Date        = "2015.05.10"
        Description = "Detects the static debug strings within CMSTAR"
        Reference   = "http://researchcenter.paloaltonetworks.com/2015/05/cmstar-downloader-lurid-and-enfals-new-cousin"

    strings:
        $d1 = "EEE\x0d\x0a" fullword
        $d2 = "TKE\x0d\x0a" fullword
        $d3 = "VPE\x0d\x0a" fullword
        $d4 = "VPS\x0d\x0a" fullword
        $d5 = "WFSE\x0d\x0a" fullword
        $d6 = "WFSS\x0d\x0a" fullword
        $d7 = "CM**\x0d\x0a" fullword

    condition:
        uint16(0) == 0x5a4d and all of ($d*)
}