rule TTP_XOR_QUAD_CurrentVersionRun_414f {
  strings:
    $key_414f = { 12 20 [2] 36 2e [2] 1d 02 [2] 33 20 [2] 27 3b [2] 28 21 [2] 36 3c [2] 34 3d [2] 2f 3b [2] 33 3c [2] 2f 13 }

  condition:
    any of them
}