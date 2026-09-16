rule TTP_XOR_QUAD_CurrentVersionRun_4850 {
  strings:
    $key_4850 = { 1b 3f [2] 3f 31 [2] 14 1d [2] 3a 3f [2] 2e 24 [2] 21 3e [2] 3f 23 [2] 3d 22 [2] 26 24 [2] 3a 23 [2] 26 0c }

  condition:
    any of them
}