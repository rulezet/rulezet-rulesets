rule PK_PayPal_it : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-12-01"
        comment = "Phishing Kit - Paypal - targets italian speakers"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "static"
                $spec_file = "conferma2.php"
        $spec_file2 = "main.js"
        $spec_file3 = "mini-spinner.php"
	    $spec_file4 = "convalida.php"
        $spec_file5 = "redirect.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                all of ($spec_file*) and 
	    all of ($spec_dir*)
}