rule APT_APT41_CRACKSHOT_RID2CA0 : APT DEMO EXE FILE G0096 crackshot {
   meta:
      description = "Detects APT41 malware CRACKSHOT"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07 09:57:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "993d14d00b1463519fea78ca65d8529663f487cd76b67b3fd35440bcdf7a8e31"
      tags = "APT, DEMO, EXE, FILE, G0096, crackshot"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = ";procmon64.exe;netmon.exe;tcpview.exe;MiniSniffer.exe;smsniff.exe" ascii
      $s1 = "RunUrlBinInMem" fullword ascii
      $s2 = "DownRunUrlFile" fullword ascii
      $s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36" fullword ascii
      $s4 = "%s|%s|%s|%s|%s|%s|%s|%dx%d|%04x|%08X|%s|%s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 250KB and ( 1 of ( $x* ) or 2 of them )
}