rule TTP_XOR_QUAD_CurrentVersionRun_666a {
  strings:
    $key_666a = { 35 05 [2] 11 0b [2] 3a 27 [2] 14 05 [2] 00 1e [2] 0f 04 [2] 11 19 [2] 13 18 [2] 08 1e [2] 14 19 [2] 08 36 }

  condition:
    any of them
}