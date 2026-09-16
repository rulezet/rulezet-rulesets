import "pe"
rule FakeNinja_v28_Spirit_additional: PEiD
{
    strings:
        $a = { BA ?? ?? ?? ?? FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 }
    condition:
        $a at pe.entry_point

}