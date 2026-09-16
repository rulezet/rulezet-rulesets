rule MAL_APT_NK_Andariel_DTrack_Unpacked {
   meta:
      author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
      description = "Detects DTrack variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      modified = "2024-07-26"
      score = 75
      id = "0c161275-2b2e-51a4-9e08-c118fb4c8671"
   strings:
      $x_str_cmd_4 = "/c systeminfo > \"%s\" & tasklist > \"%s\" & netstat -naop tcp > \"%s\"" wide
      $x_str_cmd_2 = "/c ping -n 3 127.0.01 > NUL % echo EEE > \"%s\"" wide

      $str_mutex = "MTX_Global"
      $str_cmd_1 = "/c net use \\\\" wide
      $str_cmd_3 = "/c move /y %s \\\\" wide
   condition:
            uint16(0) == 0x5A4D
      and (
         1 of ($x*)
         or 3 of them
      )
}