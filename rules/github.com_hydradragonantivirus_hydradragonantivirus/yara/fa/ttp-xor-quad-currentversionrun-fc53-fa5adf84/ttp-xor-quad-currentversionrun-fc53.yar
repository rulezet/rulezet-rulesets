rule TTP_XOR_QUAD_CurrentVersionRun_fc53 {
  strings:
    $key_fc53 = { af 3c [2] 8b 32 [2] a0 1e [2] 8e 3c [2] 9a 27 [2] 95 3d [2] 8b 20 [2] 89 21 [2] 92 27 [2] 8e 20 [2] 92 0f }

  condition:
    any of them
}