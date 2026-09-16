rule TTP_XOR_QUAD_CurrentVersionRun_e852 {
  strings:
    $key_e852 = { bb 3d [2] 9f 33 [2] b4 1f [2] 9a 3d [2] 8e 26 [2] 81 3c [2] 9f 21 [2] 9d 20 [2] 86 26 [2] 9a 21 [2] 86 0e }

  condition:
    any of them
}