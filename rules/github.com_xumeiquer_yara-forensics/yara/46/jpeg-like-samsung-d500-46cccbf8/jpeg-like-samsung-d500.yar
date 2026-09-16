rule jpeg_like_Samsung_D500: JPEG
{
    meta:
        author = "Jaume Martin"

    strings:
        $a = {FF D8 FF E3 ?? ?? 53 50 49 46 46 00}

    condition:
       $a
}