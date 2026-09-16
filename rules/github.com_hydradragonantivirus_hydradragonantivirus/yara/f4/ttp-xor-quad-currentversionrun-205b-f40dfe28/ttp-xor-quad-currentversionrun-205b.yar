rule TTP_XOR_QUAD_CurrentVersionRun_205b {
  strings:
    $key_205b = { 73 34 [2] 57 3a [2] 7c 16 [2] 52 34 [2] 46 2f [2] 49 35 [2] 57 28 [2] 55 29 [2] 4e 2f [2] 52 28 [2] 4e 07 }

  condition:
    any of them
}