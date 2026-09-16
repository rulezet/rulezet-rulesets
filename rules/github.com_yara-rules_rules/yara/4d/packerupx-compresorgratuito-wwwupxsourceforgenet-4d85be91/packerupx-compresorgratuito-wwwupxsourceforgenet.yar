import "pe"
rule PackerUPX_CompresorGratuito_wwwupxsourceforgenet: PEiD
{
    strings:
        $a = { 60 BE ?? ?0 ?? 00 8D BE ?? ?? F? FF }
    condition:
        $a at pe.entry_point

}