rule MAL_Metasploit_Framework_UA_RID316E : DEMO EXE FILE MAL METASPLOIT SUSP {
   meta:
      description = "Detects User Agent used in Metasploit Framework"
      author = "Florian Roth"
      reference = "https://github.com/rapid7/metasploit-framework/commit/12a6d67be48527f5d3987e40cac2a0cbb4ab6ce7"
      date = "2018-08-16 13:22:11"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1743e1bd4176ffb62a1a0503a0d76033752f8bd34f6f09db85c2979c04bbdd29"
      tags = "DEMO, EXE, FILE, MAL, METASPLOIT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 1 of them
}