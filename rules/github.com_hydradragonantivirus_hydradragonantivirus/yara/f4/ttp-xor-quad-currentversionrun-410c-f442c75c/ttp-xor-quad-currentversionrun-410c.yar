rule TTP_XOR_QUAD_CurrentVersionRun_410c {
  strings:
    $key_410c = { 12 63 [2] 36 6d [2] 1d 41 [2] 33 63 [2] 27 78 [2] 28 62 [2] 36 7f [2] 34 7e [2] 2f 78 [2] 33 7f [2] 2f 50 }

  condition:
    any of them
}