import "pe"
rule UPX_com_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B9 ?? ?? BE ?? ?? BF C0 FF FD }
    condition:
        $a at pe.entry_point

}