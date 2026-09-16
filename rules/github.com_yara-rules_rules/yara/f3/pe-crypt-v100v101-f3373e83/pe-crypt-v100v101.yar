import "pe"
rule PE_Crypt_v100v101: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }
    condition:
        $a at pe.entry_point

}