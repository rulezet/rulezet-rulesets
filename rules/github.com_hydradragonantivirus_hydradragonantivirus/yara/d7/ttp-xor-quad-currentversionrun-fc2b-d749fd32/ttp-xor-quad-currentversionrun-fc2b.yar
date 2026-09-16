rule TTP_XOR_QUAD_CurrentVersionRun_fc2b {
  strings:
    $key_fc2b = { af 44 [2] 8b 4a [2] a0 66 [2] 8e 44 [2] 9a 5f [2] 95 45 [2] 8b 58 [2] 89 59 [2] 92 5f [2] 8e 58 [2] 92 77 }

  condition:
    any of them
}