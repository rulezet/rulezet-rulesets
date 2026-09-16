import "pe"
rule APT_APT41_POISONPLUG_RID2D0E : APT DEMO EXE FILE G0096 {
   meta:
      description = "Detects APT41 malware POISONPLUG"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07 10:15:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2eea29d83f485897e2bac9501ef000cc266ffe10019d8c529555a3435ac4aabd"
      hash2 = "5d971ed3947597fbb7e51d806647b37d64d9fe915b35c7c9eaf79a37b82dab90"
      hash3 = "f4d57acde4bc546a10cd199c70cdad09f576fdfe66a36b08a00c19ff6ae19661"
      tags = "APT, DEMO, EXE, FILE, G0096"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "TSMSISrv.DLL" fullword wide
      $s2 = "[-]write failed[%d]" fullword ascii
      $s3 = "[-]load failed" fullword ascii
      $s4 = "Remote Desktop Services" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 10000KB and ( pe.imphash ( ) == "1b074ef7a1c0888ef31337c8ad2f2e0a" or 2 of them )
}