rule TTP_XOR_QUAD_CurrentVersionRun_666c {
  strings:
    $key_666c = { 35 03 [2] 11 0d [2] 3a 21 [2] 14 03 [2] 00 18 [2] 0f 02 [2] 11 1f [2] 13 1e [2] 08 18 [2] 14 1f [2] 08 30 }

  condition:
    any of them
}