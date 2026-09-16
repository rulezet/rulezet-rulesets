rule TTP_XOR_QUAD_CurrentVersionRun_2804 {
  strings:
    $key_2804 = { 7b 6b [2] 5f 65 [2] 74 49 [2] 5a 6b [2] 4e 70 [2] 41 6a [2] 5f 77 [2] 5d 76 [2] 46 70 [2] 5a 77 [2] 46 58 }

  condition:
    any of them
}