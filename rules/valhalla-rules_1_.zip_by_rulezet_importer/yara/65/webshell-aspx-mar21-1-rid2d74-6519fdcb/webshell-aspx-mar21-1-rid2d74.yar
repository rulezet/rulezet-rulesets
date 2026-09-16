rule WEBSHELL_ASPX_Mar21_1_RID2D74 : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects ASPX Web Shells"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-03-12 10:32:31"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-11-03"
      hash1 = "10b6e82125a2ddf3cc31a238e0d0c71a64f902e0d77171766713affede03174d"
      hash2 = "170bee832df176aac0a3c6c7d5aa3fee413b4572030a24c994a97e70f6648ffc"
      hash3 = "31c4d1fc81c052e269866deff324dffb215e7d481a47a2b6357a572a3e685d90"
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".StartInfo.FileName = 'cmd.exe';" ascii
      $s2 = "<xsl:template match=\"\"/root\"\">" ascii fullword
      $s3 = "<?xml version=\"\"1.0\"\"?><root>test</root>\";" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 6KB and all of them
}