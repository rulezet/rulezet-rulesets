rule PK_BCP_manito : BCP
{
    meta:
        description = "Phishing Kit impersonating Banco de Credito"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-08"
        comment = "Phishing Kit - BCP"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "panel"
                $spec_file = "loginx.php"
        $spec_file2 = "loli_manito_panel_style.css"
        $spec_file3 = "correo.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_dir
}