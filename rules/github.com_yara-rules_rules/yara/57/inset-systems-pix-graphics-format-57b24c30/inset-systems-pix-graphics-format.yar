import "pe"
rule Inset_Systems_PIX_Graphics_format: PEiD
{
    strings:
        $a = { 03 00 ?? 00 00 00 20 00 }
    condition:
        $a at pe.entry_point

}