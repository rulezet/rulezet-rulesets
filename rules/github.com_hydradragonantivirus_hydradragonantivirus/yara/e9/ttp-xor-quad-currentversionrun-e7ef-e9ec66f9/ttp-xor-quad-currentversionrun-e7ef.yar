rule TTP_XOR_QUAD_CurrentVersionRun_e7ef {
  strings:
    $key_e7ef = { b4 80 [2] 90 8e [2] bb a2 [2] 95 80 [2] 81 9b [2] 8e 81 [2] 90 9c [2] 92 9d [2] 89 9b [2] 95 9c [2] 89 b3 }

  condition:
    any of them
}