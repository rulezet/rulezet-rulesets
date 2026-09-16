import "pe"
rule Banners_font_file: PEiD
{
    strings:
        $a = { AB CD 00 }
    condition:
        $a at pe.entry_point

}