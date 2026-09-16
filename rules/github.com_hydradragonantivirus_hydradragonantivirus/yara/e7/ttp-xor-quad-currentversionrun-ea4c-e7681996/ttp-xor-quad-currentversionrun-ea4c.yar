rule TTP_XOR_QUAD_CurrentVersionRun_ea4c {
  strings:
    $key_ea4c = { b9 23 [2] 9d 2d [2] b6 01 [2] 98 23 [2] 8c 38 [2] 83 22 [2] 9d 3f [2] 9f 3e [2] 84 38 [2] 98 3f [2] 84 10 }

  condition:
    any of them
}