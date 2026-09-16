rule HKTL_BlueHammer_Apr26_RID2E6F : DEMO HKTL T1003 T1068 {
   meta:
      description = "Detects Nightmare-Eclipse/BlueHammer (FunnyApp), a Windows local privilege escalation PoC that abuses a Defender signature-update RPC and a junction/symlink race to leak the SAM hive and derive NTLM hashes - giving an unprivileged user full SYSTEM-level credential access."
      author = "AzizFarghly"
      reference = "https://github.com/Nightmare-Eclipse/BlueHammer"
      date = "2026-04-07 11:14:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1003, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Junction created %ws => %ws" 
      $x2 = "connect to windows defender RPC port !!!" 
      $s1 = "\\System32\\Config\\SAM" wide
      $s2 = "IMpService77BDAF73-B396-481F-9042-AD358843EC24" wide
      $s3 = "ServerMpUpdateEngineSignature" 
      $op1 = { 8D 47 02 66 89 43 0C 66 C7 43 0E 02 00 48 8B C7 48 D1 E8 66 44 89 7C 43 12 } 
   condition: 
      uint16 ( 0 ) == 0x5A4D and filesize < 7MB and ( 1 of ( $x* ) or all of ( $s* ) or $op1 ) or 3 of them
}