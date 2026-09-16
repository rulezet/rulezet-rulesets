rule ShellCrew_StreamEx_1_msi_dll_RID31F5 : APT DEMO FILE G0009 {
   meta:
      description = "Semiautomatically generated YARA rule - file msi.dll.eng"
      author = "Florian Roth"
      reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
      date = "2017-02-10 13:44:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "883108119d2f4db066fa82e37aa49ecd2dbdacda67eb936b96720663ed6565ce"
      hash2 = "5311f862d7c824d13eea8293422211e94fb406d95af0ae51358accd4835aaef8"
      hash3 = "191cbeffa36657ab1ef3939da023cacbc9de0285bbe7775069c3d6e18b372c3f"
      tags = "APT, DEMO, FILE, G0009"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "NDOGDUA" fullword ascii
      $s2 = "NsrdsrN" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x4d9d and filesize < 300KB and all of them )
}