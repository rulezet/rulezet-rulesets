rule genhash_genhash_RID2D2C : APT DEMO EXE FILE {
   meta:
      description = "Semiautomatically generated YARA rule - file genhash.exe"
      author = "Florian Roth"
      reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
      date = "2015-07-10 10:20:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "genhash.exe <password>" fullword ascii
      $s3 = "Password: %s" fullword ascii
      $s4 = "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X" fullword ascii
      $s5 = "This tool generates LM and NT hashes." fullword ascii
      $s6 = "(hashes format: LM Hash:NT hash)" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 2 of them
}