rule CN_Honker_Webshell_Injection_Transit_jmPost_RID381F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jmPost.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 18:07:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii
      $s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii
   condition: 
      filesize < 9KB and all of them
}