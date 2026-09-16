rule TTP_XOR_QUAD_CurrentVersionRun_fc7e {
  strings:
    $key_fc7e = { af 11 [2] 8b 1f [2] a0 33 [2] 8e 11 [2] 9a 0a [2] 95 10 [2] 8b 0d [2] 89 0c [2] 92 0a [2] 8e 0d [2] 92 22 }

  condition:
    any of them
}