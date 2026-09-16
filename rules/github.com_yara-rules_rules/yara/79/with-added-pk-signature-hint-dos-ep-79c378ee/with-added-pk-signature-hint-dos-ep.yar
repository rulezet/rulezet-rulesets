import "pe"
rule with_added_PK_signature_Hint_DOS_EP: PEiD
{
    strings:
        $a = { C7 ?? ?? ?? ?? ?? 8C D8 05 }
    condition:
        $a at pe.entry_point

}