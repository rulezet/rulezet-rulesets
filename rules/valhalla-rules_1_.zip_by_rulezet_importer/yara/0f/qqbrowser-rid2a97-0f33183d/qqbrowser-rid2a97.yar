rule QQBrowser_RID2A97 : APT DEMO EXE FILE {
   meta:
      description = "Not malware but suspicious browser - file QQBrowser_RID2A97.exe"
      author = "Florian Roth"
      reference = "https://blog.checkpoint.com/research/fireball-chinese-malware-250-million-infection/"
      date = "2017-06-02 07:03:21"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "adcf6b8aa633286cd3a2ce7c79befab207802dec0e705ed3c74c043dabfc604c"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "TerminateProcessWithoutDump" fullword ascii
      $s2 = ".Downloader.dll" fullword wide
      $s3 = "Software\\Chromium\\BrowserCrashDumpAttempts" fullword wide
      $s4 = "QQBrowser_RID2A97_Broker.exe" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}