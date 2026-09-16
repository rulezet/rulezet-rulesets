import "pe"
rule MicroJoiner_15_coban2k: PEiD
{
    strings:
        $a = { BF 05 10 40 00 83 EC 30 8B EC E8 C8 FF FF FF E8 C3 FF FF FF }
    condition:
        $a at pe.entry_point

}