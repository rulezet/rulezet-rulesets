rule TTP_XOR_QUAD_CurrentVersionRun_2878 {
  strings:
    $key_2878 = { 7b 17 [2] 5f 19 [2] 74 35 [2] 5a 17 [2] 4e 0c [2] 41 16 [2] 5f 0b [2] 5d 0a [2] 46 0c [2] 5a 0b [2] 46 24 }

  condition:
    any of them
}