rule CN_Honker_Without_a_trace_Wywz_RID3309 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Wywz.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:30:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\Symantec\\Norton Personal Firewall\\Log\\Content.log" ascii
      $s2 = "UpdateFile=d:\\tool\\config.ini,Option\\\\proxyIp=127.0.0.1\\r\\nproxyPort=808" ascii
      $s3 = "%s\\subinacl.exe /subkeyreg \"%s\" /Grant=%s=f /Grant=everyone=f" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1800KB and all of them
}