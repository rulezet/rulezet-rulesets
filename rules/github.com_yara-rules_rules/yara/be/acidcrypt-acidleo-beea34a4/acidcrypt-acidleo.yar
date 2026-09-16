import "pe"
rule AcidCrypt_AciDLeo: PEiD
{
    strings:
        $a = { 60 B9 ?? ?? ?? 00 BA ?? ?? ?? 00 BE ?? ?? ?? 00 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }
    condition:
        $a at pe.entry_point

}