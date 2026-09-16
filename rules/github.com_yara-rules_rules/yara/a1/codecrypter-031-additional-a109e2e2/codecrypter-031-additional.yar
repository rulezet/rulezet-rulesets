import "pe"
rule codeCrypter_031_additional: PEiD
{
    strings:
        $a = { 50 58 53 5B 90 BB ?? ?? 40 00 FF E3 90 CC CC CC 55 8B EC 5D C3 }
    condition:
        $a at pe.entry_point

}