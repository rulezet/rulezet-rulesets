rule UploadShell_98038f1efa4203432349badabad76d44337319a6_RID3657 : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "506a6ab6c49e904b4adc1f969c91e4f1a7dde164be549c6440e766de36c93215"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "$lol = file_get_contents(\"../../../../../wp-config.php\");" fullword ascii
      $s6 = "@unlink(\"./export-check-settings.php\");" fullword ascii
      $s7 = "$xos = \"Safe-mode:[Safe-mode:\".$hsafemode.\"] " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c and filesize < 6KB and ( all of ( $s* ) ) ) or ( all of them )
}