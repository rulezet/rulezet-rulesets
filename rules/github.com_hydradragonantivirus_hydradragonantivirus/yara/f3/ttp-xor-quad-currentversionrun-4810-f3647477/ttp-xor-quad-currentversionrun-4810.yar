rule TTP_XOR_QUAD_CurrentVersionRun_4810 {
  strings:
    $key_4810 = { 1b 7f [2] 3f 71 [2] 14 5d [2] 3a 7f [2] 2e 64 [2] 21 7e [2] 3f 63 [2] 3d 62 [2] 26 64 [2] 3a 63 [2] 26 4c }

  condition:
    any of them
}