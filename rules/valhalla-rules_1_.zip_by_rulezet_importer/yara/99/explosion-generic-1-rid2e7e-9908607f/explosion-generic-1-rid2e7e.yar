rule Explosion_Generic_1_RID2E7E : APT DEMO FILE G0123 GEN MIDDLE_EAST T1091 {
   meta:
      description = "Generic Rule for Explosion/Explosive Malware - Volatile Cedar APT - Autorun"
      author = "Florian Roth"
      reference = "not set"
      date = "2015-04-03 11:16:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      hash1 = "1952fa94b582e9af9dca596b5e51c585a78b8b1610639e3b878bbfa365e8e908"
      hash2 = "d8fdcdaad652c19f4f4676cd2f89ae834dbc19e2759a206044b18601875f2726"
      hash3 = "e2e6ed82703de21eb4c5885730ba3db42f3ddda8b94beb2ee0c3af61bc435747"
      tags = "APT, DEMO, FILE, G0123, GEN, MIDDLE_EAST, T1091"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "autorun.exe" fullword
      $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.1; .NET CL" 
      $s2 = "%drp.exe" fullword
      $s3 = "%s_%s%d.exe" fullword
      $s4 = "open=autorun.exe" fullword
      $s5 = "http://www.microsoft.com/en-us/default.aspx" fullword
      $s10 = "error.renamefile" fullword
      $s12 = "insufficient lookahead" fullword
      $s13 = "%s %s|" fullword
      $s16 = ":\\autorun.exe" fullword
   condition: 
      uint16 ( 0 ) == 0x5A4D and 7 of them
}