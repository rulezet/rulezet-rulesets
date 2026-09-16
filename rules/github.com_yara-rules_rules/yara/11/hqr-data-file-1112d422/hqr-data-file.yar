import "pe"
rule HQR_data_file: PEiD
{
    strings:
        $a = { 48 00 00 00 ?? 02 00 00 ?? ?? 00 00 ?? ?? 00 00 }
    condition:
        $a at pe.entry_point

}