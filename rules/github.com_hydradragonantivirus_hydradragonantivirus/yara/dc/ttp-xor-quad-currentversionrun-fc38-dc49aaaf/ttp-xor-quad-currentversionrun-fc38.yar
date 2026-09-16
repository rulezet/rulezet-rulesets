rule TTP_XOR_QUAD_CurrentVersionRun_fc38 {
  strings:
    $key_fc38 = { af 57 [2] 8b 59 [2] a0 75 [2] 8e 57 [2] 9a 4c [2] 95 56 [2] 8b 4b [2] 89 4a [2] 92 4c [2] 8e 4b [2] 92 64 }

  condition:
    any of them
}