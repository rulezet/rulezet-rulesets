import "pe"
rule Turbo_Basic_v10_1987_additional: PEiD
{
    strings:
        $a = { 2E 8C ?? ?? ?? 2E C7 }
    condition:
        $a at pe.entry_point

}