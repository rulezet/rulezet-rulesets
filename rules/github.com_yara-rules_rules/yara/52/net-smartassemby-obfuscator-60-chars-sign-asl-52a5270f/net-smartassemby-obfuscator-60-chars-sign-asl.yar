import "pe"
rule NET_SmartAssemby_Obfuscator_60_chars_sign_ASL: PEiD
{
    strings:
        $a = { 50 6F 77 65 72 65 64 20 62 79 20 53 6D 61 72 74 41 73 73 65 6D 62 6C 79 20 36 }
    condition:
        $a at pe.entry_point

}