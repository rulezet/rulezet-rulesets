import "pe"
rule APT_APT41_HIGHNOON_2_RID2CE9 : APT DEMO EXE FILE G0096 {
   meta:
      description = "Detects APT41 malware HIGHNOON"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07 10:09:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d"
      tags = "APT, DEMO, EXE, FILE, G0096"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $x1 = "H:\\RBDoor\\" ascii
      $s1 = "PlusDll.dll" fullword ascii
      $s2 = "ShutDownEvent.dll" fullword ascii
      $s3 = "\\svchost.exe" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "b70358b00dd0138566ac940d0da26a03" or pe.exports ( "DllMain_mem" ) or $x1 or 3 of them )
}