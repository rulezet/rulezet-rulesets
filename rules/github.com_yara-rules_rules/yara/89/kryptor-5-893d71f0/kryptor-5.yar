import "pe"
rule kryptor_5: PEiD
{
    strings:
        $a = { E8 03 ?? ?? ?? E9 EB 6C 58 40 FF E0 }
    condition:
        $a at pe.entry_point

}