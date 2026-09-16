rule PK_MTB_NFL : MT_Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-09-28"
        comment = "Phishing Kit - M&T Bank - 'From:  NFL <demoi@r1z.com>'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "mtbonline"
                $spec_file = "drey.php"
        $spec_file2 = "index.htm"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and
                $spec_file and
        $spec_file2 
}