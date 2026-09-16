rule TTP_XOR_QUAD_CurrentVersionRun_660d {
  strings:
    $key_660d = { 35 62 [2] 11 6c [2] 3a 40 [2] 14 62 [2] 00 79 [2] 0f 63 [2] 11 7e [2] 13 7f [2] 08 79 [2] 14 7e [2] 08 51 }

  condition:
    any of them
}