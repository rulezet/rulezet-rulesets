import "pe"
rule LY_WGKX_wwwszleyucom_: PEiD
{
    strings:
        $a = { 4D 79 46 75 6E 00 62 73 }
    condition:
        $a at pe.entry_point

}