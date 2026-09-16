rule Foudre_Backdoor_Dropper_1_RID30C5 : DEMO EXE FILE MAL T1547_001 {
   meta:
      description = "Detects Foudre Backdoor"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2017/08/unit42-prince-persia-ride-lightning-infy-returns-foudre/"
      date = "2017-08-01 12:54:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "6bc9f6ac2f6688ed63baa29913eaf8c64738cf19933d974d25a0c26b7d01b9ac"
      hash2 = "da228831089c56743d1fbc8ef156c672017cdf46a322d847a270b9907def53a5"
      tags = "DEMO, EXE, FILE, MAL, T1547_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "536F594A96C5496CB3949A4DA4775B576E049C57696E646F77735C43757272656E7456657273696F6E5C5C52756E" fullword wide
      $x2 = "2220263024C380B3278695851482EC32" fullword wide
      $s1 = "C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\\\Startup\\" wide
      $s2 = "C:\\Documents and Settings\\All Users\\" wide
      $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\\\Shell Folders" wide
      $s4 = "ShellExecuteW" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) or 4 of them ) )
}