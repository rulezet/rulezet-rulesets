rule Unknown_0f06c5d1b32f4994c3b3abf8bb76d5468f105167_RID3522 : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:00:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6362372850ac7455fa9461ed0483032a1886543f213a431f81a2ac76d383b47e"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/libraries/lola.php\" ;" fullword ascii
      $s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
      $s3 = "fwrite($fp,base64_decode('" ascii
   condition: 
      ( uint16 ( 0 ) == 0x6324 and filesize < 2KB and all of them )
}