rule MAL_APT_NK_Andariel_CutieDrop_MagicRAT {
   meta:
      author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
      description = "Detects the MagicRAT variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "104244de-83fb-5112-a2b6-e20d38a6ced6"
   strings:
            
      $config_os_w = "os/windows" ascii
      $config_os_l = "os/linux" ascii
      $config_os_m = "os/mac" ascii
      $config_comp_msft = "company/microsoft" ascii
      $config_comp_orcl = "company/oracle" ascii
      $POST_field_1 = "session=" ascii
      $POST_field_2 = "type=" ascii
            $command_misspelled = "renmae" ascii
   condition:
      uint16(0) == 0x5a4d 
      and 7 of them
}