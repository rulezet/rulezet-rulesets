rule TTP_XOR_QUAD_CurrentVersionRun_fc2c {
  strings:
    $key_fc2c = { af 43 [2] 8b 4d [2] a0 61 [2] 8e 43 [2] 9a 58 [2] 95 42 [2] 8b 5f [2] 89 5e [2] 92 58 [2] 8e 5f [2] 92 70 }

  condition:
    any of them
}