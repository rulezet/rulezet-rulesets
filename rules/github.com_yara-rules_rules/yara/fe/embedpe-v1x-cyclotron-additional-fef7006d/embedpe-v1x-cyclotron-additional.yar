import "pe"
rule EmbedPE_V1X_cyclotron_additional: PEiD
{
    strings:
        $a = { 83 EC 50 60 68 ?? ?? ?? ?? E8 ?? ?? 00 00 }
    condition:
        $a at pe.entry_point

}