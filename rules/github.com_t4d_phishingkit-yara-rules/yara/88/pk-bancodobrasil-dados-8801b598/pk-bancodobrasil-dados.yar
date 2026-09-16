rule PK_BancoDoBrasil_dados : BancoDoBrasil
{
    meta:
        description = "Phishing Kit impersonating Banco Do Brasil"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-16"
        comment = "Phishing kit impersonating BancoDoBrasil"        

    strings:
                $zip_file = { 50 4b 03 04 }
        $spec_dir = "data"
        $spec_file = "proceed.php"
        $spec_file2 = "envio2.php"
        $spec_file3 = "allow.php"
        $spec_file4 = "cartao-menor.jpg"

    condition:
                uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
                all of ($spec_file*)
}