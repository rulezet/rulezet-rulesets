rule CN_Honker_Webshell__Injection_jmCook_jmPost_ManualInjection_RID3E5C : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - from files Injection.exe, jmCook.asp, jmPost.asp, ManualInjection.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 22:33:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5e1851c77ce922e682333a3cb83b8506e1d7395d"
      hash2 = "f80ec26bbdc803786925e8e0450ad7146b2478ff"
      hash3 = "e83d427f44783088a84e9c231c6816c214434526"
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii
      $s2 = "strReturn=Replace(strReturn,chr(43),\"%2B\")  'JMDCW" fullword ascii
   condition: 
      filesize < 7342KB and all of them
}