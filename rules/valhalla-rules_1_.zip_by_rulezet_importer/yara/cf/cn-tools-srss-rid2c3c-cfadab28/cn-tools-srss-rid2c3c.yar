rule CN_Tools_srss_RID2C3C : APT CHINA DEMO SCRIPT {
   meta:
      description = "Chinese Hacktool Set - file srss.bat"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:40:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "srss.exe -idx 0 -ip" 
      $s1 = "-port 21 -logfilter \"_USER ,_P" ascii
   condition: 
      filesize < 100 and all of them
}