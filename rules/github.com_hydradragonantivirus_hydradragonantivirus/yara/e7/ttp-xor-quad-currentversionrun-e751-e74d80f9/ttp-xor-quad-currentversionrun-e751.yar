rule TTP_XOR_QUAD_CurrentVersionRun_e751 {
  strings:
    $key_e751 = { b4 3e [2] 90 30 [2] bb 1c [2] 95 3e [2] 81 25 [2] 8e 3f [2] 90 22 [2] 92 23 [2] 89 25 [2] 95 22 [2] 89 0d }

  condition:
    any of them
}