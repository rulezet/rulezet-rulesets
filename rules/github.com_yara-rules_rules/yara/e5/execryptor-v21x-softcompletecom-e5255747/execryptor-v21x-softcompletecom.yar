import "pe"
rule EXECryptor_V21X_softcompletecom: PEiD
{
    strings:
        $a = { 83 C6 14 8B 55 FC E9 ?? FF FF FF }
        $b = { E9 ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}