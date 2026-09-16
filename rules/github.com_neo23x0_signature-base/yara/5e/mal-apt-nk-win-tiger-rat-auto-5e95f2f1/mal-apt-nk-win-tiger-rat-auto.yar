rule MAL_APT_NK_WIN_Tiger_RAT_Auto {
   meta:
      author = "CISA.gov"
      description = "Detects the Tiger RAT variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 75
      id = "4579af62-52be-5f5f-a577-16ec50297c05"
    strings:
      $sequence_0 = { 33c0 89442438 89442430 448bcf 4533c0 }
                                                      
      $sequence_1 = { 41b901000000 488bd6 488bcb e8???????? }
                                             
      $sequence_2 = { 4881ec90050000 8b01 8985c8040000 8b4104 }
                                             
      $sequence_3 = { 488b01 ff10 488b4f08 4c8d4c2430 }
                                             
      $sequence_4 = { 488b01 ff10 488b4e18 488b01 }
                                             
      $sequence_5 = { 4881eca0000000 33c0 488bd9 488d4c2432 }
                                             
      $sequence_6 = { 488b01 eb03 488bc1 0fb600 }
                                             
      $sequence_7 = { 488b01 8b10 895124 448b4124 4585c0 }
                                                      
      $sequence_8 = { 4c8d0d31eb0000 c1e918 c1e808 41bf00000080 }
                                             
      $sequence_9 = { 488bd8 4885c0 752d ff15???????? 83f857 0f85e0010000 488d0da0bd0000 }
                                                                        
      $sequence_10 = { 75d4 488d1d7f6c0100 488b4bf8 4885c9 740b }
                                                      
      $sequence_11 = { 0f85d9000000 488d15d0c90000 41b810200100 488bcd e8???????? eb6b b9f4ffffff }
                                                                        
      $sequence_12 = { 48890d???????? 488905???????? 488d05ae610000 488905???????? 488d05a0550000 488905???????? }
                                                               
      $sequence_13 = { 8bcf e8???????? 488b7c2448 85c0 0f8440030000 488d0560250100 }
                                                               
      $sequence_14 = { ff15???????? 8b05???????? 2305???????? ba02000000 33c9 8905???????? 8b05???????? }
                                                                        
      $sequence_15 = { 4883ec30 498bd8 e8???????? 488bc8 4885c0 }
                                                      
    condition:
        filesize < 600KB and 7 of them
}