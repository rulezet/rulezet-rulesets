import "pe"
rule TASM_MASM: PEiD
{
    strings:
        $a = { E9 E5 E2 FF }
        $b = { 6A 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}