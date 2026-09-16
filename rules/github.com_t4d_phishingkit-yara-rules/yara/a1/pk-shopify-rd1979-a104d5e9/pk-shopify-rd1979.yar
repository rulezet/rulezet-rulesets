rule PK_Shopify_rd1979 : Shopify
{
    meta:
        description = "Phishing Kit impersonating Shopify"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-30"
        comment = "Phishing Kit - Shopify - RD1577"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "css"
        $spec_dir2 = "images"
                $spec_file = "acc.html"
        $spec_file2 = "next.php"
        $spec_file3 = "otp.html"
        $spec_file4 = "logo.svg"
        $spec_file5 = "merchant-public-b2b713b82cff21a7122558448c48f2d3b6c6d547b0ef6e80f9e43c33e7d43a82.css"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}