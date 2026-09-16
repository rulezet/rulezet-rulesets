rule PK_TrustWallet_it : TrustWallet
{
    meta:
        description = "Phishing Kit impersonating Trust Wallet"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-01-22"
        comment = "Phishing Kit - Trust Wallet - 'From:Trust W | IT <webmail@'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "trust"
                $spec_file = "trust_logotype.svg"
        $spec_file2 = "CrYpTo.php"
        $spec_file3 = "recovery.php"
        $spec_file4 = "pattern.php"


    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}