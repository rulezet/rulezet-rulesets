rule PK_Multi_mumu
{
    meta:
        description = "Phishing Kit impersonating Several brands (hotmail, hanmail, 163, AE, ...)"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-04-31"
        comment = "Phishing Kit - Multiple - found mailing-list called mumu*.txt"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "image"
                $spec_file = "process.php"
        $spec_file2 = "naver.php"
        $spec_file3 = "rediff.php"
	    $spec_file4 = "sp_btn_20140615.png"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_dir and 
        all of ($spec_file*)
}