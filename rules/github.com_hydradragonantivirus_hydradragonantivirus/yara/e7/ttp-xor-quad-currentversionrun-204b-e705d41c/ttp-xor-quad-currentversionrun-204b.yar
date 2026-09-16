rule TTP_XOR_QUAD_CurrentVersionRun_204b {
  strings:
    $key_204b = { 73 24 [2] 57 2a [2] 7c 06 [2] 52 24 [2] 46 3f [2] 49 25 [2] 57 38 [2] 55 39 [2] 4e 3f [2] 52 38 [2] 4e 17 }

  condition:
    any of them
}