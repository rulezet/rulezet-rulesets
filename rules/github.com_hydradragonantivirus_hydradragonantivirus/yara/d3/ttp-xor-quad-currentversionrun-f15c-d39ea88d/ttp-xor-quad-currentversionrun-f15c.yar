rule TTP_XOR_QUAD_CurrentVersionRun_f15c {
  strings:
    $key_f15c = { a2 33 [2] 86 3d [2] ad 11 [2] 83 33 [2] 97 28 [2] 98 32 [2] 86 2f [2] 84 2e [2] 9f 28 [2] 83 2f [2] 9f 00 }

  condition:
    any of them
}