rule PK_PayPal_l3v3lup : Paypal
{
    meta:
        description = "Phishing Kit impersonating Paypal"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-10-31"
        comment = "Phishing Kit - Paypal - 'By L3V3L UP'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "get_started"
                $spec_file = "iswrong.php"
        $spec_file2 = "fake_result.php"
        $spec_file3 = "js-plus.js"
	    $spec_file4 = "vbv.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_file4 and
	    $spec_dir
}