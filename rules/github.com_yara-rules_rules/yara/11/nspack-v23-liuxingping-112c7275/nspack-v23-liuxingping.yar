import "pe"
rule nSpack_V23_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 70 61 63 6B 24 40 }
    condition:
        $a at pe.entry_point

}