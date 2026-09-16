rule PK_BanquePostale_Fiching : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2021-07-31"
        comment = "Phishing kit - Banque Postale - '$FichingMessage = false'"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "letters"
                $spec_file = "zobiii.php"
        $spec_file2 = "crca.html"
        $spec_file3 = "merci.html"
        $spec_file4 = "certi.html"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        $spec_dir and 
                all of ($spec_file*)
}