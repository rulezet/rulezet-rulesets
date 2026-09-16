rule TTP_XOR_QUAD_CurrentVersionRun_fc18 {
  strings:
    $key_fc18 = { af 77 [2] 8b 79 [2] a0 55 [2] 8e 77 [2] 9a 6c [2] 95 76 [2] 8b 6b [2] 89 6a [2] 92 6c [2] 8e 6b [2] 92 44 }

  condition:
    any of them
}