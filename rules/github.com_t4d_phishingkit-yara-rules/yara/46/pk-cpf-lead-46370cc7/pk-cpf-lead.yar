rule PK_CPF_lead : CPF
{
    meta:
        description = "Phishing Kit impersonating MonCompteFormation(Gov. FR)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.linkedin.com/posts/thdamon_phishing-activity-7276168951955423232-bAQ_/"
        date = "2025-01-06"
        comment = "Phishing Kit - CPF - using lead.php file"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_dir = "img"
        $spec_dir2 = "css"
                $spec_file = "lead.php"
        $spec_file2 = "register.php"
        $spec_file3 = "animate.css"
        $spec_file4 = "informatique.png"
        $spec_file5 = "logo_cpf.png"

    condition:
                uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}