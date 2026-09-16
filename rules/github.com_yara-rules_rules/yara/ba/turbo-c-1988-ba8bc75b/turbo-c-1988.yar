import "pe"
rule Turbo_C_1988: PEiD
{
    strings:
        $a = { 8C D8 BB ?? ?? 8E DB 8C D3 8B CC FA 8E ?? ?? ?? BC }
    condition:
        $a at pe.entry_point

}