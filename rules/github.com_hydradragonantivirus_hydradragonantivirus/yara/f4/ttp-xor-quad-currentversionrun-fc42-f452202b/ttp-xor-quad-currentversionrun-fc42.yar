rule TTP_XOR_QUAD_CurrentVersionRun_fc42 {
  strings:
    $key_fc42 = { af 2d [2] 8b 23 [2] a0 0f [2] 8e 2d [2] 9a 36 [2] 95 2c [2] 8b 31 [2] 89 30 [2] 92 36 [2] 8e 31 [2] 92 1e }

  condition:
    any of them
}