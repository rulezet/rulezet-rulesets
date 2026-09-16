import "pe"
rule Banners_banner_file: PEiD
{
    strings:
        $a = { D1 BA 01 00 }
    condition:
        $a at pe.entry_point

}