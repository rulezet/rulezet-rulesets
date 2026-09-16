import "pe"
rule Krypton_v02_yadolockless: PEiD
{
    strings:
        $a = { 8B 0C 24 E9 0A 7C 01 00 AD 42 40 BD BE 9D 7A 04 }
    condition:
        $a at pe.entry_point

}