rule SecurityXploded_Producer_String_RID33B2 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects hacktools by SecurityXploded"
      author = "Florian Roth"
      reference = "http://securityxploded.com/browser-password-dump.php"
      date = "2017-07-13 14:58:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d57847db5458acabc87daee6f30173348ac5956eb25e6b845636e25f5a56ac59"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "http://securityxploded.com" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and all of them )
}