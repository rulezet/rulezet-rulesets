rule MAL_Information_Collector_May26_RID32C4 : DEMO EXE FILE MAL {
   meta:
      description = "Detects reconaissance payload used in the DAEMON Tools supplychain compromise. The tools collects detailed information about the infected system like hardware, installed software, running processes etc. all data is exfilled to an attacker controlled server."
      author = "MalGamy, Jonathan Peters (cod3nym)"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      date = "2026-05-05 14:19:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = ": InfoCollector.exe <" wide
      $s1 = "CollectInstalledSoftwareSemicolon" ascii
      $s2 = "GetRc4KeyFromUrl" ascii
      $s3 = "InfoGatherer" ascii
      $op1 = { 09 7E ?? ?? ?? 04 28 ?? ?? ?? 0A 28 ?? ?? ?? 0A 13 ?? 11 ?? 16 36 3A 11 ?? 1E 35 ?? 1E 8D ?? ?? ?? 01 13 ?? 09 7E ?? ?? ?? 04 28 ?? ?? ?? 0A 11 ?? 16 11 ?? 28 ?? ?? ?? 0A } 
      $op2 = { 02 73 ?? ?? ?? 0A 6F ?? ?? ?? 0A 0A 06 2D ?? 72 ?? ?? ?? 70 0B DE ?? 06 6F ?? ?? ?? 0A 0A 06 72 ?? ?? ?? 70 7E ?? ?? ?? 0A 6F ?? ?? ?? 0A 0A 06 6F ?? ?? ?? 0A 2D ?? 72 ?? ?? ?? 70 0B DE ?? 06 0B DE } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and ( $x1 or all of ( $op* ) or all of ( $s* ) )
}