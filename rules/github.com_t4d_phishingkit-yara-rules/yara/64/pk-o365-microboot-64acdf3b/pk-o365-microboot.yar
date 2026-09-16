rule PK_O365_MicroBoot
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = ""
        author = "Guido Denzler"
        reference = ""
        date = "2020-02-25"
        comment = "Phishing Kit - O365 - MICROBOOT - ICQ:703514486"

    strings:
                $local_file = { 50 4b 03 04 }
                $spec_file1 = "MP1.php"
        $spec_file2 = "sdk.php"
        $spec_image1 = "payments.png"

    condition:
                uint32(0) == 0x04034b50 
        and $local_file
        and $spec_file1 
	and $spec_file2 
        and $spec_image1
}