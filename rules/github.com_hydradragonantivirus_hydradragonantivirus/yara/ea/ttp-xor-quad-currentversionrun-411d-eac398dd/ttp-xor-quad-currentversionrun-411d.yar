rule TTP_XOR_QUAD_CurrentVersionRun_411d {
  strings:
    $key_411d = { 12 72 [2] 36 7c [2] 1d 50 [2] 33 72 [2] 27 69 [2] 28 73 [2] 36 6e [2] 34 6f [2] 2f 69 [2] 33 6e [2] 2f 41 }

  condition:
    any of them
}