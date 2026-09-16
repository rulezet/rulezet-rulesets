import "pe"
rule PCIENC_Cryptor: PEiD
{
    strings:
        $a = { 06 50 43 49 45 4E }
    condition:
        $a at pe.entry_point

}