rule TTP_XOR_QUAD_CurrentVersionRun_574b {
  strings:
    $key_574b = { 04 24 [2] 20 2a [2] 0b 06 [2] 25 24 [2] 31 3f [2] 3e 25 [2] 20 38 [2] 22 39 [2] 39 3f [2] 25 38 [2] 39 17 }

  condition:
    any of them
}