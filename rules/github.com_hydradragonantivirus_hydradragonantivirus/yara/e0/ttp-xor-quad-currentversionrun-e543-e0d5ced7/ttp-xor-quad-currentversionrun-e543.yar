rule TTP_XOR_QUAD_CurrentVersionRun_e543 {
  strings:
    $key_e543 = { b6 2c [2] 92 22 [2] b9 0e [2] 97 2c [2] 83 37 [2] 8c 2d [2] 92 30 [2] 90 31 [2] 8b 37 [2] 97 30 [2] 8b 1f }

  condition:
    any of them
}