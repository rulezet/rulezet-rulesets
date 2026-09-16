rule TTP_XOR_QUAD_CurrentVersionRun_4110 {
  strings:
    $key_4110 = { 12 7f [2] 36 71 [2] 1d 5d [2] 33 7f [2] 27 64 [2] 28 7e [2] 36 63 [2] 34 62 [2] 2f 64 [2] 33 63 [2] 2f 4c }

  condition:
    any of them
}