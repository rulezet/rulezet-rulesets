import "pe"
rule Exe_Locker_V10_IonIce: PEiD
{
    strings:
        $a = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 }
    condition:
        $a at pe.entry_point

}