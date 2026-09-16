rule TTP_XOR_QUAD_CurrentVersionRun_eb52 {
  strings:
    $key_eb52 = { b8 3d [2] 9c 33 [2] b7 1f [2] 99 3d [2] 8d 26 [2] 82 3c [2] 9c 21 [2] 9e 20 [2] 85 26 [2] 99 21 [2] 85 0e }

  condition:
    any of them
}