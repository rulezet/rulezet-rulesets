rule PK_Uber_wabz : Uber
{
    meta:
        description = "Phishing Kit impersonating Uber"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-03-16"
        comment = "Phishing Kit - Uber - 'output started at /home/uberwabz/public_html/' - using Telegram to exfil"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "anti"
                $spec_file = "captured.txt"
        $spec_file2 = "index4.php"
        $spec_file3 = "id.php"
        $spec_file4 = "anti3.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}