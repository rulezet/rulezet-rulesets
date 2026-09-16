rule MAL_APT_NK_Andariel_BindShell {
   meta:
      author = "CISA.gov"
      description = "Detects a BindShell used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 70
      id = "3f6d83da-cea5-5e12-b0ba-93ace09d3d5c"
   strings:
      $str_comspec = "COMSPEC"
      $str_consolewindow = "GetConsoleWindow"
      $str_ShowWindow = "ShowWindow"
      $str_WSASocketA = "WSASocketA"
      $str_CreateProcessA = "CreateProcessA"
      $str_port = { B9 4D 05 00 00 89 }
   condition:
      uint16(0) == 0x5A4D 
      and all of them
}