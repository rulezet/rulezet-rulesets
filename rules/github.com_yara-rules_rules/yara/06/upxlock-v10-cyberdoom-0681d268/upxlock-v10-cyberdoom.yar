import "pe"
rule UPXLock_v10_CyberDoom: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 60 E8 2B 03 00 00 }
    condition:
        $a at pe.entry_point

}