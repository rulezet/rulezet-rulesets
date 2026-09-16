rule WebShell_5786d7d9f4b0df731d79ed927fb5a124195fc901_RID355F : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:10:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b1733cbb0eb3d440c4174cc67ca693ba92308ded5fc1069ed650c3c78b1da4bc"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "preg_replace(\"\\x2F\\x2E\\x2A\\x2F\\x65\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x" ascii
      $s2 = "input[type=text], input[type=password]{" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x6c3c and filesize < 80KB and all of them )
}