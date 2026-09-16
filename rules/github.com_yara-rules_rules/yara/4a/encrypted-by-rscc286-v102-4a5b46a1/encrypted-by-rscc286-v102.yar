import "pe"
rule Encrypted_by_RSCC286_v102: PEiD
{
    strings:
        $a = { FE 52 53 43 43 2F 31 2E 30 32 FE }
    condition:
        $a at pe.entry_point

}