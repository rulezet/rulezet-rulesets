import "pe"
rule kryptor_9_additional: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5E B9 ?? ?? ?? ?? 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }
    condition:
        $a at pe.entry_point

}