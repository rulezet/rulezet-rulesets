rule PK_PayPal_ShadowZ118 : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-01-01"
        comment = "Phishing Kit - Paypal - Shadow Z118 v1.10 - scam Paypal"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "functions"
                $spec_file = "FULLZ_CARD.php"
        $spec_file2 = "V-Z118.js"
        $spec_file3 = "14303695_853354554765349_388275294_o.jpg"
	    $spec_file4 = "badge-512.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4 and
	    $spec_dir
}