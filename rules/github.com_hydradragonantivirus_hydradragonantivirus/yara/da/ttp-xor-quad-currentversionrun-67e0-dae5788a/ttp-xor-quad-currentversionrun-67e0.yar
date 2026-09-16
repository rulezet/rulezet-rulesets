rule TTP_XOR_QUAD_CurrentVersionRun_67e0 {
  strings:
    $key_67e0 = { 34 8f [2] 10 81 [2] 3b ad [2] 15 8f [2] 01 94 [2] 0e 8e [2] 10 93 [2] 12 92 [2] 09 94 [2] 15 93 [2] 09 bc }

  condition:
    any of them
}