import "pe"
rule UPX_072_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E }
    condition:
        $a at pe.entry_point

}