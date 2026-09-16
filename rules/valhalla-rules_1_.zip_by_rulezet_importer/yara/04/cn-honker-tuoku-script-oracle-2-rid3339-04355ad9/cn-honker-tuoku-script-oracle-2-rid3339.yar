rule CN_Honker_Tuoku_script_oracle_2_RID3339 : CHINA DEMO HKTL SCRIPT {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file oracle.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:38:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, HKTL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "webshell" fullword ascii
      $s1 = "Silic Group Hacker Army " fullword ascii
   condition: 
      filesize < 3KB and all of them
}