import "pe"
rule DrHalo_or_DrGenius_Image_Graphics_format: PEiD
{
    strings:
        $a = { ?? ?? 3A 03 00 00 }
        $b = { 3A 03 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}