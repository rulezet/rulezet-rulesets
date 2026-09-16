import "pe"
rule Embed_PE_v113_cyclotron: PEiD
{
    strings:
        $a = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 }
    condition:
        $a at pe.entry_point

}