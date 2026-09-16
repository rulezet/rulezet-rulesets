import "pe"
rule Banners_banner_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { D1 BA 01 00 }
    condition:
        $a at pe.entry_point

}