rule TTP_XOR_QUAD_CurrentVersionRun_4840 {
  strings:
    $key_4840 = { 1b 2f [2] 3f 21 [2] 14 0d [2] 3a 2f [2] 2e 34 [2] 21 2e [2] 3f 33 [2] 3d 32 [2] 26 34 [2] 3a 33 [2] 26 1c }

  condition:
    any of them
}