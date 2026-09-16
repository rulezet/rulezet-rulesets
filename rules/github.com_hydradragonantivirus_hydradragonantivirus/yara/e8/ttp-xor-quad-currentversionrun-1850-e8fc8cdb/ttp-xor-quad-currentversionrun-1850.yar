rule TTP_XOR_QUAD_CurrentVersionRun_1850 {
  strings:
    $key_1850 = { 4b 3f [2] 6f 31 [2] 44 1d [2] 6a 3f [2] 7e 24 [2] 71 3e [2] 6f 23 [2] 6d 22 [2] 76 24 [2] 6a 23 [2] 76 0c }

  condition:
    any of them
}