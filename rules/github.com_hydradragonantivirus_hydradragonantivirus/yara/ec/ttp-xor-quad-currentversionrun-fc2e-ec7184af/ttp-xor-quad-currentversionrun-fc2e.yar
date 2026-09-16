rule TTP_XOR_QUAD_CurrentVersionRun_fc2e {
  strings:
    $key_fc2e = { af 41 [2] 8b 4f [2] a0 63 [2] 8e 41 [2] 9a 5a [2] 95 40 [2] 8b 5d [2] 89 5c [2] 92 5a [2] 8e 5d [2] 92 72 }

  condition:
    any of them
}