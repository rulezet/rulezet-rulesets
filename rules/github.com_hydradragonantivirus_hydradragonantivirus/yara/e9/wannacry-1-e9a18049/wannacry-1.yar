rule wannacry_1 : ransom
{
meta:
author = "Joshua Cannell"
description = "WannaCry Ransomware strings"
reference = "https://securingtomorrow.mcafee.com/executive-perspectives/analysis-wannacry-ransomware-outbreak/"
weight = 100
date = "2017-05-12"
 
strings:
$s1 = "Ooops, your files have been encrypted!" wide ascii nocase
$s2 = "Wanna Decryptor" wide ascii nocase
$s3 = ".wcry" wide ascii nocase
$s4 = "WANNACRY" wide ascii nocase
$s5 = "WANACRY!" wide ascii nocase
$s7 = "icacls . /grant Everyone:F /T /C /Q" wide ascii nocase
 
condition:
any of them
}