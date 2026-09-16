import "pe"
rule PE_Crypt_v100v101_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 }
    condition:
        $a at pe.entry_point

}