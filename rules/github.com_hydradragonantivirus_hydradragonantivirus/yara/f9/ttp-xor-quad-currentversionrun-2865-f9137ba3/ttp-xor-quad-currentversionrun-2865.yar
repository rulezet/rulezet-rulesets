rule TTP_XOR_QUAD_CurrentVersionRun_2865 {
  strings:
    $key_2865 = { 7b 0a [2] 5f 04 [2] 74 28 [2] 5a 0a [2] 4e 11 [2] 41 0b [2] 5f 16 [2] 5d 17 [2] 46 11 [2] 5a 16 [2] 46 39 }

  condition:
    any of them
}