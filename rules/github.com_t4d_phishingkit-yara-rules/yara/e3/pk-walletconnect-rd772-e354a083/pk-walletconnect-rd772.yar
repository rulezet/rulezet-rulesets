rule PK_WalletConnect_RD772 : WalletConnect
{
    meta:
        description = "Phishing Kit impersonating WalletConnect"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-04"
        comment = "Phishing Kit - WalletConnect - using 'wallet-restoration-RD772' directory"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "images"
        $spec_dir2 = "css"
                $spec_file = "restore.html"
        $spec_file2 = "bar.html"
        $spec_file3 = "next.php"
        $spec_file4 = "coin98.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}