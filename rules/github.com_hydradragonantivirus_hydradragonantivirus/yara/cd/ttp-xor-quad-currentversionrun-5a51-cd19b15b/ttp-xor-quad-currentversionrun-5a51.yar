rule TTP_XOR_QUAD_CurrentVersionRun_5a51 {
  strings:
    $key_5a51 = { 09 3e [2] 2d 30 [2] 06 1c [2] 28 3e [2] 3c 25 [2] 33 3f [2] 2d 22 [2] 2f 23 [2] 34 25 [2] 28 22 [2] 34 0d }

  condition:
    any of them
}