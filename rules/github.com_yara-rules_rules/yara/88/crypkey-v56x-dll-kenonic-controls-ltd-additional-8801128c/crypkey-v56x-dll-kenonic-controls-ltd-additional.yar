import "pe"
rule CrypKey_V56X_DLL_Kenonic_Controls_Ltd_additional: PEiD
{
    strings:
        $a = { 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA }
    condition:
        $a at pe.entry_point

}