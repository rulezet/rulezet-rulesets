rule TTP_XOR_QUAD_CurrentVersionRun_e704 {
  strings:
    $key_e704 = { b4 6b [2] 90 65 [2] bb 49 [2] 95 6b [2] 81 70 [2] 8e 6a [2] 90 77 [2] 92 76 [2] 89 70 [2] 95 77 [2] 89 58 }

  condition:
    any of them
}