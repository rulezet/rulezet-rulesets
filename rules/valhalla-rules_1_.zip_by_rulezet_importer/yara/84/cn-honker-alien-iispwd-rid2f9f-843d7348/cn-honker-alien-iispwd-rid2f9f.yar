rule CN_Honker_Alien_iispwd_RID2F9F : CHINA DEMO HKTL SCRIPT {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file iispwd.vbs"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:05:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, HKTL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "set IIs=objservice.GetObject(\"IIsWebServer\",childObjectName)" fullword ascii
      $s1 = "wscript.echo \"from : http://www.xxx.com/\" &vbTab&vbCrLf" fullword ascii
   condition: 
      filesize < 3KB and all of them
}