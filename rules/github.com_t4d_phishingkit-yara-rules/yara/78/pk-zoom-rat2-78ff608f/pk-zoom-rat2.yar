rule PK_Zoom_rat2: Zoom
{
    meta:
        description = "Phishing Kit impersonating Zoom for RAT distribution"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-07-22"
        comment = "Phishing Kit - Zoom - distributng Remote Access Tool"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "Windows"
        $spec_dir2 = "Iphone"
        $spec_dir3 = "Android"
        $spec_file = "Google-play.html"
        $spec_file2 = "install-guide.php"
        $spec_file3 = "ms-store.php"
        $spec_file4 = "invite.php"
        $spec_file5 = "zoom-icon.webp"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}