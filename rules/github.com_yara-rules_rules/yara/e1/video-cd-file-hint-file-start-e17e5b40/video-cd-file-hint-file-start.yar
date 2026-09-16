import "pe"
rule Video_CD_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 43 44 58 41 66 6D 74 }
    condition:
        $a at pe.entry_point

}