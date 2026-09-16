rule PK_Mooney_hexor : Mooney
{
    meta:
        description = "Phishing Kit impersonating Mooney.it"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-06-09"
        comment = "Phishing Kit - Mooney - using '$hexor' variable"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "online"
        $spec_dir2 = "del"

                $spec_file = "incsms.php"
        $spec_file2 = "TelegramApi.php"
        $spec_file3 = "hexor.css"
        $spec_file4 = "logo-mooney.1330f350147445f5103b36dac80a6726.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}