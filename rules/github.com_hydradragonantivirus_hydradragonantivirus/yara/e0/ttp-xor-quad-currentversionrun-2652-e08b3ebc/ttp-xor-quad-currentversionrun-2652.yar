rule TTP_XOR_QUAD_CurrentVersionRun_2652 {
  strings:
    $key_2652 = { 75 3d [2] 51 33 [2] 7a 1f [2] 54 3d [2] 40 26 [2] 4f 3c [2] 51 21 [2] 53 20 [2] 48 26 [2] 54 21 [2] 48 0e }

  condition:
    any of them
}