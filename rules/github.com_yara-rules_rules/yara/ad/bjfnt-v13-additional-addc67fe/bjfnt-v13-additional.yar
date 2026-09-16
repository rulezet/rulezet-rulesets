import "pe"
rule BJFnt_v13_additional: PEiD
{
    strings:
        $a = { EB ?? 2E 90 ?? ?? 8C DB 8C CA 8E DA FA 8B EC BE ?? ?? BC ?? ?? BF }
    condition:
        $a at pe.entry_point

}