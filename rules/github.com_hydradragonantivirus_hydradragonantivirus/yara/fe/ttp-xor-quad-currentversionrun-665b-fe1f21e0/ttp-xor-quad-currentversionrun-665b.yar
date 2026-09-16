rule TTP_XOR_QUAD_CurrentVersionRun_665b {
  strings:
    $key_665b = { 35 34 [2] 11 3a [2] 3a 16 [2] 14 34 [2] 00 2f [2] 0f 35 [2] 11 28 [2] 13 29 [2] 08 2f [2] 14 28 [2] 08 07 }

  condition:
    any of them
}