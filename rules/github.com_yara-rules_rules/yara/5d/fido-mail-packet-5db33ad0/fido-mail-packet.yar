import "pe"
rule FIDO_mail_packet: PEiD
{
    strings:
        $a = { 03 00 03 00 CD 07 }
    condition:
        $a at pe.entry_point

}