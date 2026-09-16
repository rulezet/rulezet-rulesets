import "pe"
rule Banners_font_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { AB CD 00 }
    condition:
        $a at pe.entry_point

}