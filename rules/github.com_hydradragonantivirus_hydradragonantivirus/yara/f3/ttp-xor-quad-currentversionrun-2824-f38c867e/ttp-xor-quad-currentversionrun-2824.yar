rule TTP_XOR_QUAD_CurrentVersionRun_2824 {
  strings:
    $key_2824 = { 7b 4b [2] 5f 45 [2] 74 69 [2] 5a 4b [2] 4e 50 [2] 41 4a [2] 5f 57 [2] 5d 56 [2] 46 50 [2] 5a 57 [2] 46 78 }

  condition:
    any of them
}