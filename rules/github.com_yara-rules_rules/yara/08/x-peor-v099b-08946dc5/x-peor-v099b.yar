import "pe"
rule X_PEOR_v099b: PEiD
{
    strings:
        $a = { E8 00 00 00 00 5D 8B CD 81 ED 7A 29 40 00 89 AD 0F 6D 40 00 }
    condition:
        $a at pe.entry_point

}