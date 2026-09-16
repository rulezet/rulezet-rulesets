import "pe"
rule Safengine_Licenseor_1720_Nooby: PEiD
{
    strings:
        $a = { E8 1B 00 00 00 53 00 61 00 66 00 65 00 6E 00 67 00 69 00 6E 00 65 00 20 00 4C 00 69 00 63 00 65 }
    condition:
        $a at pe.entry_point

}