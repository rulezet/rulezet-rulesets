rule TTP_XOR_QUAD_CurrentVersionRun_eced {
  strings:
    $key_eced = { bf 82 [2] 9b 8c [2] b0 a0 [2] 9e 82 [2] 8a 99 [2] 85 83 [2] 9b 9e [2] 99 9f [2] 82 99 [2] 9e 9e [2] 82 b1 }

  condition:
    any of them
}