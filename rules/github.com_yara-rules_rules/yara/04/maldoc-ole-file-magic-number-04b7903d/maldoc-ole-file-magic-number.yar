rule maldoc_OLE_file_magic_number : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {D0 CF 11 E0}
    condition:
        $a
}