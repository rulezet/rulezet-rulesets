rule MAL_APT_NK_Andariel_LilithRAT_Variant {
   meta:
      author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
      description = "Detects a variant of the Lilith RAT malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      modified = "2024-07-26"
      score = 80
      id = "916a289b-db7b-5f09-9d3e-589c3f09101d"
   strings:
            
            $lilith_1 = "Initiate a CMD session first." ascii
      $lilith_2 = "CMD is not open" ascii
      $lilith_3 = "Couldn't write command" ascii
      $lilith_4 = "Couldn't write to CMD: CMD not open" ascii

            $unique_1 = "Upload Error!" ascii
      $unique_2 = "ERROR: Downloading is already running!" ascii
      $unique_3 = "ERROR: Unable to open file:" ascii
      $unique_4 = "General error" ascii
      $unique_5 = "CMD error" ascii
      $unique_6 = "killing self" ascii
   condition:
            uint16(0) == 0x5a4d 
      and filesize < 150KB 
      and ( 
         all of ($lilith_*) 
         or 4 of ($unique_*)
         or 1 of ($lilith_4, $unique_2)       ) 
}