rule TTP_XOR_QUAD_CurrentVersionRun_e77b {
  strings:
    $key_e77b = { b4 14 [2] 90 1a [2] bb 36 [2] 95 14 [2] 81 0f [2] 8e 15 [2] 90 08 [2] 92 09 [2] 89 0f [2] 95 08 [2] 89 27 }

  condition:
    any of them
}