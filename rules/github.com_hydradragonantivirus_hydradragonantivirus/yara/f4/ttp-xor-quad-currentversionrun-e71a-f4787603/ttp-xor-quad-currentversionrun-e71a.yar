rule TTP_XOR_QUAD_CurrentVersionRun_e71a {
  strings:
    $key_e71a = { b4 75 [2] 90 7b [2] bb 57 [2] 95 75 [2] 81 6e [2] 8e 74 [2] 90 69 [2] 92 68 [2] 89 6e [2] 95 69 [2] 89 46 }

  condition:
    any of them
}