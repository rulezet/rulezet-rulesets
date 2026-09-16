rule TTP_XOR_QUAD_CurrentVersionRun_730c {
  strings:
    $key_730c = { 20 63 [2] 04 6d [2] 2f 41 [2] 01 63 [2] 15 78 [2] 1a 62 [2] 04 7f [2] 06 7e [2] 1d 78 [2] 01 7f [2] 1d 50 }

  condition:
    any of them
}