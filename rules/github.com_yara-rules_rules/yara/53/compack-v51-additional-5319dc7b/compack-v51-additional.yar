import "pe"
rule COMPACK_v51_additional: PEiD
{
    strings:
        $a = { BD ?? ?? 50 06 8C CB 03 DD 8C D2 4B 8E DB BE ?? ?? BF ?? ?? 8E C2 B9 ?? ?? F3 A5 4A 4D 75 ?? 8B F7 8E DA 0E 07 06 16 }
    condition:
        $a at pe.entry_point

}