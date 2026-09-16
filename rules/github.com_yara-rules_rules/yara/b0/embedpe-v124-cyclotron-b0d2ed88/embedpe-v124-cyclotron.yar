import "pe"
rule EmbedPE_v124_cyclotron: PEiD
{
    strings:
        $a = { 83 EC 50 60 68 ?? ?? ?? ?? E8 CB FF 00 00 }
    condition:
        $a at pe.entry_point

}