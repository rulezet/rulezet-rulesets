rule TTP_XOR_QUAD_CurrentVersionRun_f052 {
  strings:
    $key_f052 = { a3 3d [2] 87 33 [2] ac 1f [2] 82 3d [2] 96 26 [2] 99 3c [2] 87 21 [2] 85 20 [2] 9e 26 [2] 82 21 [2] 9e 0e }

  condition:
    any of them
}