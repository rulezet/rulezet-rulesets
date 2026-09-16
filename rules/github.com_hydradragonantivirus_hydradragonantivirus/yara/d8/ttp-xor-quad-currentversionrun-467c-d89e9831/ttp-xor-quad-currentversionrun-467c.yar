rule TTP_XOR_QUAD_CurrentVersionRun_467c {
  strings:
    $key_467c = { 15 13 [2] 31 1d [2] 1a 31 [2] 34 13 [2] 20 08 [2] 2f 12 [2] 31 0f [2] 33 0e [2] 28 08 [2] 34 0f [2] 28 20 }

  condition:
    any of them
}