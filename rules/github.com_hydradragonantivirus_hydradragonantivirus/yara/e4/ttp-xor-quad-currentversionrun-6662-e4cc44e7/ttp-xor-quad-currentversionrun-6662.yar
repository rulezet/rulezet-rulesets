rule TTP_XOR_QUAD_CurrentVersionRun_6662 {
  strings:
    $key_6662 = { 35 0d [2] 11 03 [2] 3a 2f [2] 14 0d [2] 00 16 [2] 0f 0c [2] 11 11 [2] 13 10 [2] 08 16 [2] 14 11 [2] 08 3e }

  condition:
    any of them
}