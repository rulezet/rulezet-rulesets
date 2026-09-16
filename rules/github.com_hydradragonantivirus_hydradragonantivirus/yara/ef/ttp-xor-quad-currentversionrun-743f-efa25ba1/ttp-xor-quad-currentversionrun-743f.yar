rule TTP_XOR_QUAD_CurrentVersionRun_743f {
  strings:
    $key_743f = { 27 50 [2] 03 5e [2] 28 72 [2] 06 50 [2] 12 4b [2] 1d 51 [2] 03 4c [2] 01 4d [2] 1a 4b [2] 06 4c [2] 1a 63 }

  condition:
    any of them
}