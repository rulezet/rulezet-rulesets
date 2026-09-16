rule TTP_XOR_QUAD_CurrentVersionRun_ed52 {
  strings:
    $key_ed52 = { be 3d [2] 9a 33 [2] b1 1f [2] 9f 3d [2] 8b 26 [2] 84 3c [2] 9a 21 [2] 98 20 [2] 83 26 [2] 9f 21 [2] 83 0e }

  condition:
    any of them
}