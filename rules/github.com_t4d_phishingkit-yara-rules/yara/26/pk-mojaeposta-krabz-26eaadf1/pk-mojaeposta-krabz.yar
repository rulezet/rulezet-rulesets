rule PK_MojaEposta_krabz : PostaSK
{
    meta:
        description = "Phishing Kit impersonating Posta.sk"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-20"
        comment = "Phishing Kit - Posta.sk - 'Telegram bot name: Mr.Krabz'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "img"
        $spec_dir2 = "prevents"
        $spec_dir3 = "common"

                $spec_file = "error.php"
        $spec_file2 = "billing-info.php"
        $spec_file3 = "loading-visa-verification.php"
        $spec_file4 = "3d secure visa.php"
        $spec_file5 = "sub_includes.php"
        $spec_file6 = "filter.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and
        all of ($spec_dir*)
}