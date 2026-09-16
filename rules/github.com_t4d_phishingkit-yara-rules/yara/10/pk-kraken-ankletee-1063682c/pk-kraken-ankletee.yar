rule PK_Kraken_ankletee : Kraken
{
    meta:
        description = "Phishing Kit impersonating Kraken"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-07"
        comment = "Phishing Kit - Kraken - 'Return of Ankletee'"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "uploaded_files"
        $spec_dir2 = "wallet"
        $spec_dir3 = "system"
                $spec_file = "send_Phrase.php"
        $spec_file2 = "Cefi login.php"
        $spec_file3 = "otp.php"
        $spec_file4 = "kraken form.php"
        $spec_file5 = "kraken.png"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}