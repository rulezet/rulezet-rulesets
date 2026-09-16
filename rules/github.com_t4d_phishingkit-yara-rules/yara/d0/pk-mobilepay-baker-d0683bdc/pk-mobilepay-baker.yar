rule PK_MobilePay_baker : MobilePay
{
    meta:
        description = "Phishing Kit impersonating Mobile Pay"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-01-10"
        comment = "Phishing Kit - MobilePay - 'https://t.me/BAK34_TMW'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "numero_fichiers"
        $spec_dir2 = "CPR_fichiers"

                $spec_file = "loding.htm"
        $spec_file2 = "CPR.htm"
        $spec_file3 = "bak3r.php"
        $spec_file4 = "mika.jfif"
        $spec_file5 = "step-four.php"
        $spec_file6 = "mobilepay.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}