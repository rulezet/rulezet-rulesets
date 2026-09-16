rule TTP_XOR_QUAD_CurrentVersionRun_1c52 {
  strings:
    $key_1c52 = { 4f 3d [2] 6b 33 [2] 40 1f [2] 6e 3d [2] 7a 26 [2] 75 3c [2] 6b 21 [2] 69 20 [2] 72 26 [2] 6e 21 [2] 72 0e }

  condition:
    any of them
}