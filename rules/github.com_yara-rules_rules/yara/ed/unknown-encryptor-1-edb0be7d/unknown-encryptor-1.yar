import "pe"
rule Unknown_encryptor_1: PEiD
{
    strings:
        $a = { EB ?? 2E 90 ?? ?? 8C DB 8C CA 8E DA FA 8B EC BE ?? ?? BC ?? ?? BF }
    condition:
        $a at pe.entry_point

}