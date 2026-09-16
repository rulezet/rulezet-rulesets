import "pe"
rule EXECryptor_V21X_softcompletecom_: PEiD
{
    strings:
        $a = { 83 C6 14 8B 55 FC E9 ?? FF FF FF }
    condition:
        $a at pe.entry_point

}