rule PK_WhatsApp_Group_Invite_Berbagi : WhatsApp
{
    meta:
        description = "Phishing Kit impersonating WhatsApp"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2019-11-28"
        comment = "Phishing Kit - WhatsApp group invite - Berbagi"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "pastel"
                $spec_file = "snd2.php" nocase

    condition:
                uint32(0) == 0x04034b50 and
                $local_file and
                $spec_file and
                $spec_dir
}