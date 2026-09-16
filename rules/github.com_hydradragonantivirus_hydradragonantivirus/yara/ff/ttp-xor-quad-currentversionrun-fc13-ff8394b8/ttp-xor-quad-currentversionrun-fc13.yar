rule TTP_XOR_QUAD_CurrentVersionRun_fc13 {
  strings:
    $key_fc13 = { af 7c [2] 8b 72 [2] a0 5e [2] 8e 7c [2] 9a 67 [2] 95 7d [2] 8b 60 [2] 89 61 [2] 92 67 [2] 8e 60 [2] 92 4f }

  condition:
    any of them
}