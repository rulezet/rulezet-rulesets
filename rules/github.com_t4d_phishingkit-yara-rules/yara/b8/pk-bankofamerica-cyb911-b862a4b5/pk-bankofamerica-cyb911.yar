rule PK_BankOfAmerica_cyb911 : BankOfAmerica
{
    meta:
        description = "Phishing Kit impersonating Bank Of America"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-01-09"
        comment = "Phishing Kit - BankOfAmerica - by '@cyb911'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "funcations.php"
        $spec_file2 = "maillist.txt"
        $spec_file3 = "getrefrer.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3
}