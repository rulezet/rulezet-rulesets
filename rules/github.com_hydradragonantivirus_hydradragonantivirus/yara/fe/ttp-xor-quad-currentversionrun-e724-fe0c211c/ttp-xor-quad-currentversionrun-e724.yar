rule TTP_XOR_QUAD_CurrentVersionRun_e724 {
  strings:
    $key_e724 = { b4 4b [2] 90 45 [2] bb 69 [2] 95 4b [2] 81 50 [2] 8e 4a [2] 90 57 [2] 92 56 [2] 89 50 [2] 95 57 [2] 89 78 }

  condition:
    any of them
}