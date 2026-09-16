rule Hacktools_CN_Burst_Blast_RID306D : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Disclosed hacktool set - file Blast.bat"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-17 12:39:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http:" ascii
      $s1 = "@echo off" fullword ascii
   condition: 
      all of them
}