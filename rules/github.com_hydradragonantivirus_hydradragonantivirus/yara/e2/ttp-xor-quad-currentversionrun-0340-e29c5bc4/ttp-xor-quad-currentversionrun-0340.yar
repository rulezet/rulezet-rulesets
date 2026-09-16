rule TTP_XOR_QUAD_CurrentVersionRun_0340 {
  strings:
    $key_0340 = { 50 2f [2] 74 21 [2] 5f 0d [2] 71 2f [2] 65 34 [2] 6a 2e [2] 74 33 [2] 76 32 [2] 6d 34 [2] 71 33 [2] 6d 1c }

  condition:
    any of them
}