rule PK_WalletConnect_only4biz : WalletConnect
{
    meta:
        description = "Phishing Kit impersonating WalletConnect"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1580117526830514176"
        date = "2022-10-12"
        comment = "Phishing Kit - WalletConnect - 'www.only4biz.org'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
        $spec_dir2 = "connect"
                $spec_file = "index-2.html"
        $spec_file2 = "finish.php"
        $spec_file3 = "aave.jpg"
        $spec_file4 = "indexff05ff05ff05ff05.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}