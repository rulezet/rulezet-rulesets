rule Unknown_8af033424f9590a15472a23cc3236e68070b952e_RID345B : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 15:27:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3382b5eaaa9ad651ab4793e807032650667f9d64356676a16ae3e9b02740ccf3"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$check = $_SERVER['DOCUMENT_ROOT']" fullword ascii
      $s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
      $s3 = "fwrite($fp,base64_decode('" ascii
   condition: 
      ( uint16 ( 0 ) == 0x6324 and filesize < 6KB and ( all of ( $s* ) ) ) or ( all of them )
}