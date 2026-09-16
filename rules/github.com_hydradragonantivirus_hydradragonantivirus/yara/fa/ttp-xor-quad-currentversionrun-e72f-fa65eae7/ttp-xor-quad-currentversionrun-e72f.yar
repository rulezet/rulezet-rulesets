rule TTP_XOR_QUAD_CurrentVersionRun_e72f {
  strings:
    $key_e72f = { b4 40 [2] 90 4e [2] bb 62 [2] 95 40 [2] 81 5b [2] 8e 41 [2] 90 5c [2] 92 5d [2] 89 5b [2] 95 5c [2] 89 73 }

  condition:
    any of them
}