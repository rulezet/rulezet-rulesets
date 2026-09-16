rule SnakeTurla_Installd_SH {
   meta:
      description = "Detects Snake / Turla Sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/QaOh4V"
      date = "2017-05-04"
      id = "65a97c0d-5c69-5e58-9a18-10e5684bc218"
   strings:
      $s1 = "PIDS=`ps cax | grep installdp" ascii
      $s2 = "${SCRIPT_DIR}/installdp ${FILE}" ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 20KB and all of them )
}