rule TTP_XOR_QUAD_CurrentVersionRun_f352 {
  strings:
    $key_f352 = { a0 3d [2] 84 33 [2] af 1f [2] 81 3d [2] 95 26 [2] 9a 3c [2] 84 21 [2] 86 20 [2] 9d 26 [2] 81 21 [2] 9d 0e }

  condition:
    any of them
}