rule TTP_XOR_QUAD_CurrentVersionRun_0c1b {
  strings:
    $key_0c1b = { 5f 74 [2] 7b 7a [2] 50 56 [2] 7e 74 [2] 6a 6f [2] 65 75 [2] 7b 68 [2] 79 69 [2] 62 6f [2] 7e 68 [2] 62 47 }

  condition:
    any of them
}