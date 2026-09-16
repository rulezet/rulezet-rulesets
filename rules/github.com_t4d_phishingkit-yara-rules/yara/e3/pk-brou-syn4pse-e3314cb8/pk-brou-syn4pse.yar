rule PK_BROU_syn4pse : BROU
{
    meta:
        description = "Phishing Kit impersonating BROU - Banco Republica"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-11-29"
        comment = "Phishing kit - BROU - 'C0DE BY SYN4PSE'"        

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = "cerezi"
        $spec_dir2 = "movyle"
        $spec_dir3 = "jotaj"
                $spec_file = "crgs2.php"
        $spec_file2 = "DONDECAE.php"
        $spec_file3 = "toka3.php"
        $spec_file4 = "fns.php"
        $spec_file5 = "elfondito.jpg"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}