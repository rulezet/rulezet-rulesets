rule TTP_XOR_QUAD_CurrentVersionRun_e74f {
  strings:
    $key_e74f = { b4 20 [2] 90 2e [2] bb 02 [2] 95 20 [2] 81 3b [2] 8e 21 [2] 90 3c [2] 92 3d [2] 89 3b [2] 95 3c [2] 89 13 }

  condition:
    any of them
}