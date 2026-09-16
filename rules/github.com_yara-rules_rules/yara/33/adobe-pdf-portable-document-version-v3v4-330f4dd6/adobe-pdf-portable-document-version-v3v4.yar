import "pe"
rule Adobe_PDF_Portable_document_Version_v3v4: PEiD
{
    strings:
        $a = { 25 50 44 46 2D ?? 2E }
    condition:
        $a at pe.entry_point

}