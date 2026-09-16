import "pe"
rule UPX_Alternative_stub_additional: PEiD
{
    strings:
        $a = { B9 ?? ?? BE ?? ?? BF C0 FF FD }
    condition:
        $a at pe.entry_point

}