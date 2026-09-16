import "pe"
rule T_PACK_v05c_m2_additional: PEiD
{
    strings:
        $a = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 CE FD }
    condition:
        $a at pe.entry_point

}