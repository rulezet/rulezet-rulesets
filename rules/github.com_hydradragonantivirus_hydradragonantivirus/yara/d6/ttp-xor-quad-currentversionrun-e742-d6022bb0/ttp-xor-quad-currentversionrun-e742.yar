rule TTP_XOR_QUAD_CurrentVersionRun_e742 {
  strings:
    $key_e742 = { b4 2d [2] 90 23 [2] bb 0f [2] 95 2d [2] 81 36 [2] 8e 2c [2] 90 31 [2] 92 30 [2] 89 36 [2] 95 31 [2] 89 1e }

  condition:
    any of them
}