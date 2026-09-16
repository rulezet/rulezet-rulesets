rule PK_Shaw_aeroplan : Shaw
{
    meta:
        description = "Phishing Kit impersonating Shaw.ca"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-03-08"
        comment = "Phishing Kit - Shaw - redirect to aeroplan"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "shaw"
        $spec_dir2 = "successfully"
                $spec_file = "index_login.html"
        $spec_file2 = "aeroplan-logo.svg"
        $spec_file3 = "form1.php"
        $spec_file4 = "radio-jazz-online24.png"
        $spec_file5 = "icomoond41d.eot"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}