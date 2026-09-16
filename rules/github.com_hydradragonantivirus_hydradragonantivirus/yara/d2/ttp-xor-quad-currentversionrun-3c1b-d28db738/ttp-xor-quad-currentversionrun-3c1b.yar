rule TTP_XOR_QUAD_CurrentVersionRun_3c1b {
  strings:
    $key_3c1b = { 6f 74 [2] 4b 7a [2] 60 56 [2] 4e 74 [2] 5a 6f [2] 55 75 [2] 4b 68 [2] 49 69 [2] 52 6f [2] 4e 68 [2] 52 47 }

  condition:
    any of them
}