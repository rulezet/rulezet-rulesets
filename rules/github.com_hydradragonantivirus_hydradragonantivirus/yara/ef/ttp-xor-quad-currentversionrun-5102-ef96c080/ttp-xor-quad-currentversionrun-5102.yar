rule TTP_XOR_QUAD_CurrentVersionRun_5102 {
  strings:
    $key_5102 = { 02 6d [2] 26 63 [2] 0d 4f [2] 23 6d [2] 37 76 [2] 38 6c [2] 26 71 [2] 24 70 [2] 3f 76 [2] 23 71 [2] 3f 5e }

  condition:
    any of them
}