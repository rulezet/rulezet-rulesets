import "pe"
rule Lotus_Word_Pro_document_file_additional: PEiD
{
    strings:
        $a = { 57 6F 72 64 50 72 6F ?? ?? ?? ?? ?? ?? ?? ?? ?? 4C 57 50 37 }
    condition:
        $a at pe.entry_point

}