rule CN_Honker_Injection_Transit_jmCook_RID3470 : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file jmCook.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:30:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".Open \"POST\",PostUrl,False" fullword ascii
      $s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii
   condition: 
      filesize < 9KB and all of them
}