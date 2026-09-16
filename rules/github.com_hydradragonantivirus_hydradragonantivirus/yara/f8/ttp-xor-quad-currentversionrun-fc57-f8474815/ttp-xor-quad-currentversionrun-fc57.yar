rule TTP_XOR_QUAD_CurrentVersionRun_fc57 {
  strings:
    $key_fc57 = { af 38 [2] 8b 36 [2] a0 1a [2] 8e 38 [2] 9a 23 [2] 95 39 [2] 8b 24 [2] 89 25 [2] 92 23 [2] 8e 24 [2] 92 0b }

  condition:
    any of them
}