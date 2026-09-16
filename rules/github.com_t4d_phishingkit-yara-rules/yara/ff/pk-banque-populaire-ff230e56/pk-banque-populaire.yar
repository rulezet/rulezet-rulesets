rule PK_Banque_Populaire : Banque Populaire
{
    meta:
        description = "Phishing Kit impersonating Banque Populaire"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2019-12-28"
        comment = "Phishing kit impersonating Banque Populaire"        

    strings:
                $local_file = { 50 4b 03 04 }
        $spec_file = "BP_Picto_service-securise.png"
        $spec_file2 = "play_cyberplus.svg" nocase

    condition:
                uint32(0) == 0x04034b50 and
                $local_file and
                $spec_file and
                $spec_file2
}