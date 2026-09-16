rule TTP_XOR_QUAD_CurrentVersionRun_e726 {
  strings:
    $key_e726 = { b4 49 [2] 90 47 [2] bb 6b [2] 95 49 [2] 81 52 [2] 8e 48 [2] 90 55 [2] 92 54 [2] 89 52 [2] 95 55 [2] 89 7a }

  condition:
    any of them
}