rule PK_Qantas_elmojrem : Qantas
{
    meta:
        description = "Phishing Kit impersonating Qantas"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-12"
        comment = "Phishing Kit - Qantas - 'BY ELMOJREM'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "KAMIHAMIHA"
        $spec_dir1 = "portal"
                $spec_file = "otp.php"
        $spec_file2 = "q_tabligh.php"
        $spec_file3 = "westpack.php"
        $spec_file4 = "ing_step1.php"
        $spec_file5 = "qantas-masterbrand-logo-40px.svg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}