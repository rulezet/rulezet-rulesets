import "pe"
rule EXECryptor_V22X_softcompletecom_: PEiD
{
    strings:
        $a = { FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 00 }
    condition:
        $a at pe.entry_point

}