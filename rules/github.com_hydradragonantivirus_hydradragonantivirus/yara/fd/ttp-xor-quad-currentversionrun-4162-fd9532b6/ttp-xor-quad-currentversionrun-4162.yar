rule TTP_XOR_QUAD_CurrentVersionRun_4162 {
  strings:
    $key_4162 = { 12 0d [2] 36 03 [2] 1d 2f [2] 33 0d [2] 27 16 [2] 28 0c [2] 36 11 [2] 34 10 [2] 2f 16 [2] 33 11 [2] 2f 3e }

  condition:
    any of them
}