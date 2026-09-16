rule TTP_XOR_QUAD_CurrentVersionRun_7a52 {
  strings:
    $key_7a52 = { 29 3d [2] 0d 33 [2] 26 1f [2] 08 3d [2] 1c 26 [2] 13 3c [2] 0d 21 [2] 0f 20 [2] 14 26 [2] 08 21 [2] 14 0e }

  condition:
    any of them
}