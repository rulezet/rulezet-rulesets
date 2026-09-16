rule TTP_XOR_QUAD_CurrentVersionRun_5150 {
  strings:
    $key_5150 = { 02 3f [2] 26 31 [2] 0d 1d [2] 23 3f [2] 37 24 [2] 38 3e [2] 26 23 [2] 24 22 [2] 3f 24 [2] 23 23 [2] 3f 0c }

  condition:
    any of them
}