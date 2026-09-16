rule TTP_XOR_QUAD_CurrentVersionRun_2817 {
  strings:
    $key_2817 = { 7b 78 [2] 5f 76 [2] 74 5a [2] 5a 78 [2] 4e 63 [2] 41 79 [2] 5f 64 [2] 5d 65 [2] 46 63 [2] 5a 64 [2] 46 4b }

  condition:
    any of them
}