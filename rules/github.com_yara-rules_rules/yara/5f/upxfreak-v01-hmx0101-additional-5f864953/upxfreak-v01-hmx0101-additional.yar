import "pe"
rule UPXFreak_V01_HMX0101_additional: PEiD
{
    strings:
        $a = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 }
    condition:
        $a at pe.entry_point

}