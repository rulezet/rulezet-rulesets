import "pe"
rule FCRYPT_v100_1990_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? 50 53 51 BE ?? ?? BF ?? ?? 8B EF B9 ?? ?? FC AC 32 C1 AA E2 ?? 59 5B 58 FF }
    condition:
        $a at pe.entry_point

}