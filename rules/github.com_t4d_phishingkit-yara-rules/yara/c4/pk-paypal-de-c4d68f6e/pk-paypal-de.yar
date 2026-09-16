rule PK_PayPal_de : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-09"
        comment = "Phishing Kit - Paypal - targeting DE speakers"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "static"
                $spec_file = "conferma2.php"
        $spec_file2 = "convalida.php"
        $spec_file3 = "redirect.php"
	    $spec_file4 = "spinner.php"
        $spec_file5 = "Icon"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and 
	    all of ($spec_dir*)
}