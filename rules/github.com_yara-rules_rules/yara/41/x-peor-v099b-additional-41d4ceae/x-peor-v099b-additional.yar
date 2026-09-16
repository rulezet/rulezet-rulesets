import "pe"
rule X_PEOR_v099b_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40 }
    condition:
        $a at pe.entry_point

}