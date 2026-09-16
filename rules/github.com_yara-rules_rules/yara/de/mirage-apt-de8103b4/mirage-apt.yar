rule Mirage_APT
{
    meta:
        Author      = "Silas Cutler"
        Date        = "yyyy/mm/dd"
        Description = "Malware related to APT campaign"
        Reference   = "Useful link"
    
    strings:
        $a1 = "welcome to the desert of the real"
        $a2 = "Mirage"
        $b = "Encoding: gzip"
        $c = /\/[A-Za-z]*\?hl=en/

    condition: 
        (($a1 or $a2) or $b) and $c
}