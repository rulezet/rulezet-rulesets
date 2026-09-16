import "pe"
rule ASPack_v10804_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? EB }
    condition:
        $a at pe.entry_point

}