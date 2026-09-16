import "pe"
rule BGI_Stroked_Font_v11_Hint_FILE_START: PEiD
{
    strings:
        $a = { 50 4B 08 08 42 47 49 20 53 74 72 6F 6B 65 64 20 46 6F 6E 74 20 56 31 2E 31 }
    condition:
        $a at pe.entry_point

}