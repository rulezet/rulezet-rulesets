import "pe"
rule UPX_Protector_v10x_2_additional: PEiD
{
    strings:
        $a = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }
    condition:
        $a at pe.entry_point

}