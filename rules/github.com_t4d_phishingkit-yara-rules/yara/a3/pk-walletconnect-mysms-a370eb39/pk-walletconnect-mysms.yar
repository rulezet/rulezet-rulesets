rule PK_WalletConnect_mysms : WalletConnect
{
    meta:
        description = "Phishing Kit impersonating WalletConnect"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-04"
        comment = "Phishing Kit - WalletConnect - using 'api.mysmssender.com' service for exfiltration"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "wallets"
        $spec_dir2 = "exchange"
                $spec_file = "icn-token-pocket.jpg"
        $spec_file2 = "wallet-connect.html"
        $spec_file3 = "index-2.html"
        $spec_file4 = "wallets.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and
                all of ($spec_file*)
}