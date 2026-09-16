rule PK_Shopify_rd1463 : Shopify
{
    meta:
        description = "Phishing Kit impersonating Shopify"
        licence = "GPL-3.0"
        author = "Thomas 'Damonneville"
        reference = ""
        date = "2023-09-25"
        comment = "Phishing Kit - Shopify - RD1463"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "icons"
                $spec_file = "card.html"
        $spec_file2 = "next.php"
        $spec_file3 = "em.html"
        $spec_file4 = "logo.svg"
        $spec_file5 = "merchant-public-74905ef98de85e0ffeaf97e73e3acecf947ca5834def49b15c5cb54ddc6323ce.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}