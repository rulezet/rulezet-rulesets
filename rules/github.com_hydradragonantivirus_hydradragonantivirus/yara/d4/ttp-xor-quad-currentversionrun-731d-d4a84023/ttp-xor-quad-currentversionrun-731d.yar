rule TTP_XOR_QUAD_CurrentVersionRun_731d {
  strings:
    $key_731d = { 20 72 [2] 04 7c [2] 2f 50 [2] 01 72 [2] 15 69 [2] 1a 73 [2] 04 6e [2] 06 6f [2] 1d 69 [2] 01 6e [2] 1d 41 }

  condition:
    any of them
}