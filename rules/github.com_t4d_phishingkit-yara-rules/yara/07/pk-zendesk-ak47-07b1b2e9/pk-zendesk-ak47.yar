rule PK_Zendesk_ak47: Zendesk
{
    meta:
        description = "Phishing Kit impersonating Zendesk"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-13"
        comment = "Phishing Kit - Zendesk - 'From: Ak47.BUlLETS'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "assets"
        $spec_dir2 = "bootstrap"
        $spec_file = "shond.php"
        $spec_file2 = "shondxt.php"
        $spec_file3 = "HLQckvmEStzm0YAHgTac1694910463.png"
        $spec_file4 = "Login-Box-En-login-box-en.css"
        $spec_file5 = "zendesksupport.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}