import "pe"
rule UPX_wwwupxsourceforgenet_additional: PEiD
{
    strings:
        $a = { 60 BE ?? ?? ?? 00 8D BE ?? ?? ?? FF }
    condition:
        $a at pe.entry_point

}