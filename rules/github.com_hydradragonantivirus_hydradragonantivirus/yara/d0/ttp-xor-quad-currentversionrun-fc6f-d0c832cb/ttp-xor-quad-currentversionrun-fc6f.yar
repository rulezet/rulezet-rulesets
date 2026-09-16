rule TTP_XOR_QUAD_CurrentVersionRun_fc6f {
  strings:
    $key_fc6f = { af 00 [2] 8b 0e [2] a0 22 [2] 8e 00 [2] 9a 1b [2] 95 01 [2] 8b 1c [2] 89 1d [2] 92 1b [2] 8e 1c [2] 92 33 }

  condition:
    any of them
}