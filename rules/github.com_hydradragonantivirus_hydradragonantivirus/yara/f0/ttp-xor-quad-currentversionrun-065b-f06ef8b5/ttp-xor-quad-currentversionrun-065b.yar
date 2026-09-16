rule TTP_XOR_QUAD_CurrentVersionRun_065b {
  strings:
    $key_065b = { 55 34 [2] 71 3a [2] 5a 16 [2] 74 34 [2] 60 2f [2] 6f 35 [2] 71 28 [2] 73 29 [2] 68 2f [2] 74 28 [2] 68 07 }

  condition:
    any of them
}