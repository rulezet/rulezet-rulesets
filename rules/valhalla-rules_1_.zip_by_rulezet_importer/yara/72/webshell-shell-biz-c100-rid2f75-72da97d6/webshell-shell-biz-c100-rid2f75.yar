rule Webshell_Shell_Biz_c100_RID2F75 : DEMO SCRIPT T1087_001 T1105 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c99-shadows-mod.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:58:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "27786d1e0b1046a1a7f67ee41c64bf4c"
      hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
      tags = "DEMO, SCRIPT, T1087_001, T1105, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "if ($data{0} == \"\\x99\" and $data{1} == \"\\x01\") {return \"Error: \".$stri" 
      $s3 = "<OPTION VALUE=\"find /etc/ -type f -perm -o+w 2> /dev/null\"" 
      $s4 = "<OPTION VALUE=\"cat /proc/version /proc/cpuinfo\">CPUINFO" fullword
      $s7 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/de" 
      $s9 = "<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER" 
   condition: 
      2 of them
}