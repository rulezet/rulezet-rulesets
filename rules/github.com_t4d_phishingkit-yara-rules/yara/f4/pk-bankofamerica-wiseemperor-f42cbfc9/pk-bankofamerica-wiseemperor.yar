rule PK_BankOfAmerica_WiseEmperor : BankOfAmerica
{
    meta:
        description = "Phishing Kit impersonating Bank Of America"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2020-01-09"
        comment = "Phishing Kit - BankOfAmerica - 'Toolz By Wise Emperor'"

    strings:
                $zip_file = { 50 4b 03 04 }
                $spec_file = "qes.php"
        $spec_file2 = "fin.php"
        $spec_file3 = "buss.php"

    condition:
                uint32(0) == 0x04034b50 and
                $zip_file and
                $spec_file and
        $spec_file2 and
        $spec_file3
}