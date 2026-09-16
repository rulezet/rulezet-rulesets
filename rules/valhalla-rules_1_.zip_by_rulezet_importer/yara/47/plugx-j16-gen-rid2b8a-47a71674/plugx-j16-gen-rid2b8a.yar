rule PlugX_J16_Gen_RID2B8A : DEMO EXE FILE GEN MAL plugx {
   meta:
      description = "Detects PlugX Malware samples from June 2016"
      author = "Florian Roth"
      reference = "MISP 3954"
      date = "2016-06-08 09:10:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "00119101c6acdd8f4c5db4a9ac4772957aaf35958daf4a2ba6ad2b3719ab4f34"
      hash2 = "005afae5aa5beec765e74b461177dce8342067c29985ef9c683af7e2d92eeef0"
      hash3 = "0109d7a8d76993ca8af111ff6fcf96021c9250cd59717151fbd4bb3792bedc12"
      tags = "DEMO, EXE, FILE, GEN, MAL, plugx"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "%WINDIR%\\SYSTEM32\\SERVICES.EXE" fullword wide
      $x2 = "\\\\.\\PIPE\\RUN_AS_USER(%d)" fullword wide
      $x3 = "LdrLoadShellcode" fullword ascii
      $x4 = "Protocol:[%4s], Host: [%s:%d], Proxy: [%d:%s:%d:%s:%s]" fullword ascii
      $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\User Agent\\Post Platform" fullword wide
      $s2 = "%s\\msiexec.exe %d %d" fullword wide
      $s3 = "l%s\\sysprep\\CRYPTBASE.DLL" fullword wide
      $s4 = "%s\\msiexec.exe UAC" fullword wide
      $s5 = "CRYPTBASE.DLL" fullword wide
      $s6 = "%ALLUSERSPROFILE%\\SxS" fullword wide
      $s7 = "%s\\sysprep\\sysprep.exe" fullword wide
      $s8 = "\\\\.\\pipe\\a%d" fullword wide
      $s9 = "\\\\.\\pipe\\b%d" fullword wide
      $s10 = "EName:%s,EAddr:0x%p,ECode:0x%p,EAX:%p,EBX:%p,ECX:%p,EDX:%p,ESI:%p,EDI:%p,EBP:%p,ESP:%p,EIP:%p" fullword ascii
      $s11 = "Mozilla/4.0 (compatible; MSIE " fullword wide
      $s12 = "; Windows NT %d.%d" fullword wide
      $s13 = "SOFTWARE\\Microsoft\\Internet Explorer\\Version Vector" fullword wide
      $s14 = "\\bug.log" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( 1 of ( $x* ) or 4 of ( $s* ) ) ) or ( 8 of them )
}