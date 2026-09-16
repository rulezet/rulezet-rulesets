rule PK_Facebook_sarthak : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-29"
        comment = "Phishing Kit - Facebook - 'Username: PhishingAttack@protonmail.com Pass: @HackerSarthak'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "mobile_files"
                $spec_file = "mobile.html"
        $spec_file1 = "victim_ip.txt"
        $spec_file2 = "login.php"
        $spec_file3 = "login_info.txt"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}