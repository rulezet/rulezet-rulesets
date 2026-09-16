import "pe"
rule UPXLock_v11_CyberDoom_Bob: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? 00 60 }
    condition:
        $a at pe.entry_point

}