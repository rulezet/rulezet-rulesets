rule SnakeTurla_Installd_SH_RID2F9F : DEMO FILE G0010 MAL RUSSIA SCRIPT {
   meta:
      description = "Detects Snake / Turla Sample"
      author = "Florian Roth"
      reference = "https://blog.fox-it.com/2017/05/03/snake-coming-soon-in-mac-os-x-flavour/"
      date = "2017-05-04 12:05:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, FILE, G0010, MAL, RUSSIA, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "PIDS=`ps cax | grep installdp" ascii
      $s2 = "${SCRIPT_DIR}/installdp ${FILE}" ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 20KB and all of them )
}