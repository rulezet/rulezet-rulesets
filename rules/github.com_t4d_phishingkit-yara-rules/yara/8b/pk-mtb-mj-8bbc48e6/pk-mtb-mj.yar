rule PK_MTB_mj : MT_Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-24"
        comment = "Phishing Kit - M&T Bank - '-  XXX-MJ  -'"

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "fonts"
                $spec_file = "mandtpg-iconfont.woff"
        $spec_file2 = "mandtbaltoweb-book.woff"
        $spec_file3 = "index.html"
        $spec_file4 = "___.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*) 
}