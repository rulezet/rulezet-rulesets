import "pe"
rule themida_1005_http58wwworeanscom: PEiD
{
    strings:
        $a = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 }
    condition:
        $a at pe.entry_point

}