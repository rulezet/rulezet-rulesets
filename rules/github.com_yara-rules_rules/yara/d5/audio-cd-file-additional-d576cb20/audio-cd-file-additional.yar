import "pe"
rule Audio_CD_file_additional: PEiD
{
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 43 44 44 41 66 6D 74 }
    condition:
        $a at pe.entry_point

}