rule TTP_XOR_QUAD_CurrentVersionRun_3c6b {
  strings:
    $key_3c6b = { 6f 04 [2] 4b 0a [2] 60 26 [2] 4e 04 [2] 5a 1f [2] 55 05 [2] 4b 18 [2] 49 19 [2] 52 1f [2] 4e 18 [2] 52 37 }

  condition:
    any of them
}