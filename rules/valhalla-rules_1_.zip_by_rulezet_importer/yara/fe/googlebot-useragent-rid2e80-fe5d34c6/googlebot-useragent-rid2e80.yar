rule GoogleBot_UserAgent_RID2E80 : DEMO EXE FILE MAL {
   meta:
      description = "Detects the GoogleBot UserAgent String in an Executable"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-27 11:17:11"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii
      $fp1 = "McAfee, Inc." wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and $x1 and not 1 of ( $fp* ) )
}