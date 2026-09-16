rule TTP_XOR_QUAD_CurrentVersionRun_730d {
  strings:
    $key_730d = { 20 62 [2] 04 6c [2] 2f 40 [2] 01 62 [2] 15 79 [2] 1a 63 [2] 04 7e [2] 06 7f [2] 1d 79 [2] 01 7e [2] 1d 51 }

  condition:
    any of them
}