import "pe"
rule CC_v261_Beta: PEiD
{
    strings:
        $a = { BA ?? ?? B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB }
    condition:
        $a at pe.entry_point

}