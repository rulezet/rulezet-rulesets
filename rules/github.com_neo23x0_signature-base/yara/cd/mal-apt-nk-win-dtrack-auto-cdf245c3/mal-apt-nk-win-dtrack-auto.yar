rule MAL_APT_NK_WIN_DTrack_Auto {
   meta:
      author = "CISA.gov"
      description = "Detects DTrack variant used by Andariel"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 75
      id = "1b40c685-beba-50fa-b484-c1526577cb23"
   strings:
      $sequence_0 = { 52 8b4508 50 e8???????? 83c414 8b4d10 51 }
                                                                        
      $sequence_1 = { 3a4101 7523 83854cf6ffff02 838550f6ffff02 80bd4af6ffff00 75ae c78544f6ffff00000000 }
                                                                        
      $sequence_2 = { 50 ff15???????? a3???????? 68???????? e8???????? 83c404 50 }
                                                                        
      $sequence_3 = { 8d8dd4faffff 51 e8???????? 83c408 8b15???????? }
                                                      
      $sequence_4 = { 8855f5 6a5c 8b450c 50 e8???????? }
                                                      
      $sequence_5 = { 51 e8???????? 83c410 8b558c 52 }
                                                      
      $sequence_6 = { 8b4d0c 51 68???????? 8d9560eaffff 52 e8???????? }
                                                               
      $sequence_7 = { 83c001 8945f4 837df420 7d2c 8b4df8 }
                                                      
      $sequence_8 = { 83c001 89856cf6ffff 8b8d70f6ffff 8a11 }
                                             
      $sequence_9 = { 0355f0 0fb602 0fb64df7 33c1 0fb655fc 33c2 }
                                                               
      $sequence_10 = { d1e9 894df8 8b5518 8955fc c745f000000000 }
                                                      
      $sequence_11 = { 8b4df0 3b4d10 0f8d90000000 8b5508 0355f0 0fb602 }
                                                               
      $sequence_12 = { 894d14 8b45f8 c1e018 8b4dfc c1e908 0bc1 }
                                                               
      $sequence_13 = { 0bc1 894518 8b5514 8955f8 }
                                             
      $sequence_14 = { 8b5514 8955f8 8b4518 8945fc e9???????? 8be5 }
                                                               
   condition:
      filesize < 1700KB and 7 of them
}