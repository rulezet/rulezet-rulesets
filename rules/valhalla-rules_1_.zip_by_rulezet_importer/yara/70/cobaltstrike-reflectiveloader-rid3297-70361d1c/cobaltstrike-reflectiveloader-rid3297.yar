import "pe"
rule CobaltStrike_ReflectiveLoader_RID3297 : APT COBALTSTRIKE DEMO EXE FILE S0154 T1105 T1550_002 {
   meta:
      description = "Detects reflective loader (Cobalt Strike)"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23 14:11:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1097bf8f5b832b54c81c1708327a54a88ca09f7bdab4571f1a335cc26bbd7904"
      hash2 = "1f52d643e8e633026db73db55eb1848580de00a203ee46263418f02c6bdb8c7a"
      hash3 = "a159a9bfb938de686f6aced37a2f7fa62d6ff5e702586448884b70804882b32f"
      tags = "APT, COBALTSTRIKE, DEMO, EXE, FILE, S0154, T1105, T1550_002"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $x1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $x2 = "%d is an x86 process (can't inject x64 content)" fullword ascii
      $x3 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
      $x4 = "Failed to impersonate token from %d (%u)" fullword ascii
      $x5 = "Failed to impersonate logged on user %d (%u)" fullword ascii
      $x6 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and 1 of them ) or ( 2 of them ) or pe.exports ( "_ReflectiveLoader@4" )
}