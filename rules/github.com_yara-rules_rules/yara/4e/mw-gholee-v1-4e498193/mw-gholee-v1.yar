rule MW_gholee_v1 : v1
{
meta:
    Author = "@GelosSnake"
    description = "http://securityaffairs.co/wordpress/28170/cyber-crime/gholee-malware.html"
    date = "2014-08"
    maltype = "Remote Access Trojan"
    sample_filetype = "dll"
    hash0 = "48573a150562c57742230583456b4c02"
   
strings:
    $a = "sandbox_avg10_vc9_SP1_2011"
    $b = "gholee"
   
condition:
    all of them
}