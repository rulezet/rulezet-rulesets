import "pe"
rule ASProtect_v11_additional: PEiD
{
    strings:
        $a = { 90 60 E8 1B ?? ?? ?? E9 FC }
    condition:
        $a at pe.entry_point

}