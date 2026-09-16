rule CN_Honker_Intersect2_Beta_RID3085 : CHINA DEMO FILE SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file Intersect2-Beta.py"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:43:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "os.system(\"ls -alhR /home > AllUsers.txt\")" fullword ascii
      $s2 = "os.system('getent passwd > passwd.txt')" fullword ascii
      $s3 = "os.system(\"rm -rf credentials/\")" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x2123 and filesize < 50KB and 2 of them
}