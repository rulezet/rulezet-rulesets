rule TTP_XOR_QUAD_CurrentVersionRun_736a {
  strings:
    $key_736a = { 20 05 [2] 04 0b [2] 2f 27 [2] 01 05 [2] 15 1e [2] 1a 04 [2] 04 19 [2] 06 18 [2] 1d 1e [2] 01 19 [2] 1d 36 }

  condition:
    any of them
}