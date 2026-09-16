import "pe"
rule v02Packer_ttt_additional: PEiD
{
    strings:
        $a = { 60 E8 36 FE FF FF C3 90 ?? 00 }
    condition:
        $a at pe.entry_point

}