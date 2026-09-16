rule PK_EDD_prncpal : EDD
{
    meta:
        description = "Phishing Kit impersonating Employment Development Department California (EDD)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-30"
        comment = "Phishing Kit - EDD - 'EDD UI ONLINE-Prncpal'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "edd_fonts"
        $spec_dir2 = "ca_images"
                $spec_file = "2fa2.html"
        $spec_file2 = "info_dl.html"
        $spec_file3 = "me.php"
        $spec_file4 = "cagov.core.js"
        $spec_file5 = "myEDD-BG-2.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}