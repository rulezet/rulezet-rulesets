rule PK_PayPal_drfxnd : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-28"
        comment = "Phishing Kit - Paypal - '-- DrFXND --'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "home"
        $spec_dir2 = "send"
        $spec_dir3 = "Chapta"
                $spec_file = "spam.php"
        $spec_file2 = "bank.php"
        $spec_file3 = "smsact.php"
	    $spec_file4 = "aa.css"
        $spec_file5 = "paypal_venmo.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and 
	    all of ($spec_dir*)
}