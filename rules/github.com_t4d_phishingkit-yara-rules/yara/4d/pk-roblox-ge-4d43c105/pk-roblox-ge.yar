rule PK_Roblox_ge : Roblox
{
    meta:
        description = "Phishing Kit impersonating Roblox"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-10"
        comment = "Phishing Kit - Roblox - georgian messages"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_dir = ".idea"
        $spec_dir2 = "7936348760"
                $spec_file = "shevida.js"
        $spec_file2 = "userprofile.html"
        $spec_file3 = "login.html"
        
    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
        all of ($spec_dir*) and 
                all of ($spec_file*)
}