rule TTP_XOR_QUAD_CurrentVersionRun_2918 {
  strings:
    $key_2918 = { 7a 77 [2] 5e 79 [2] 75 55 [2] 5b 77 [2] 4f 6c [2] 40 76 [2] 5e 6b [2] 5c 6a [2] 47 6c [2] 5b 6b [2] 47 44 }

  condition:
    any of them
}