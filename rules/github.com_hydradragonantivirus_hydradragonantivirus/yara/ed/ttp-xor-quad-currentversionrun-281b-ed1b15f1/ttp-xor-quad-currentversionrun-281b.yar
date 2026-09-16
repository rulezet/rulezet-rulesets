rule TTP_XOR_QUAD_CurrentVersionRun_281b {
  strings:
    $key_281b = { 7b 74 [2] 5f 7a [2] 74 56 [2] 5a 74 [2] 4e 6f [2] 41 75 [2] 5f 68 [2] 5d 69 [2] 46 6f [2] 5a 68 [2] 46 47 }

  condition:
    any of them
}