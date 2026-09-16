rule TTP_XOR_QUAD_CurrentVersionRun_1462 {
  strings:
    $key_1462 = { 47 0d [2] 63 03 [2] 48 2f [2] 66 0d [2] 72 16 [2] 7d 0c [2] 63 11 [2] 61 10 [2] 7a 16 [2] 66 11 [2] 7a 3e }

  condition:
    any of them
}