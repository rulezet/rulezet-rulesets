import "pe"
rule NsPack_V2X_LiuXingPing: PEiD
{
    strings:
        $a = { 6E 73 70 61 63 6B 24 40 }
    condition:
        $a at pe.entry_point

}