rule PK_WalletConnect_js : WalletConnect
{
    meta:
        description = "Phishing Kit impersonating WalletConnect"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-16"
        comment = "Phishing Kit - WalletConnect - using a JS file with email credentials inside"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
        $spec_dir2 = "connect"
                $spec_file = "index-2.html"
        $spec_file2 = "app.js"
        $spec_file3 = "Blockchain.png"
        $spec_file4 = "indexff05ff05.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}