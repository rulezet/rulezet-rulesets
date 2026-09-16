import "pe"
rule File_Analyser_14_Encryptor: PEiD
{
    strings:
        $a = { B9 00 00 B3 00 33 D2 BE 00 00 8B FE AC 32 C3 AA 49 43 32 E4 03 D0 E3 }
    condition:
        $a at pe.entry_point

}