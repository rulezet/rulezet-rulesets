rule TTP_XOR_QUAD_CurrentVersionRun_f152 {
  strings:
    $key_f152 = { a2 3d [2] 86 33 [2] ad 1f [2] 83 3d [2] 97 26 [2] 98 3c [2] 86 21 [2] 84 20 [2] 9f 26 [2] 83 21 [2] 9f 0e }

  condition:
    any of them
}