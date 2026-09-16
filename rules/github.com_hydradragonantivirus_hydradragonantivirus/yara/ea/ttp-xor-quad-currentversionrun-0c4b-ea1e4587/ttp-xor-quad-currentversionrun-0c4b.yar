rule TTP_XOR_QUAD_CurrentVersionRun_0c4b {
  strings:
    $key_0c4b = { 5f 24 [2] 7b 2a [2] 50 06 [2] 7e 24 [2] 6a 3f [2] 65 25 [2] 7b 38 [2] 79 39 [2] 62 3f [2] 7e 38 [2] 62 17 }

  condition:
    any of them
}