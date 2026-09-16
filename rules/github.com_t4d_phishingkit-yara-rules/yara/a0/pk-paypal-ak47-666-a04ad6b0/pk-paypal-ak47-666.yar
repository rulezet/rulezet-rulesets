rule PK_PayPal_AK47_666 : PayPal
{
    meta:
        description = "Phishing Kit impersonating PayPal"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = "https://thequickredfox.ca/2020/01/05/walkthrough-of-the-ppl-v7-paypal-phishing-kit/"
        date = "2021-01-21"
        comment = "Phishing Kit - PayPal - 'AK47-VbV' version '666'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "proof"
                $spec_file = "algo.php"
        $spec_file2 = "bank.php"
        $spec_file3 = "identity.php"
        $spec_file4 = "mailprovider.php"
        $spec_file5 = "signin.js"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}