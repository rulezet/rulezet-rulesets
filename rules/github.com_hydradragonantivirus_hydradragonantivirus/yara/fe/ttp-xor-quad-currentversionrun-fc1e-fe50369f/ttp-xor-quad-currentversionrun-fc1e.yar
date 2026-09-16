rule TTP_XOR_QUAD_CurrentVersionRun_fc1e {
  strings:
    $key_fc1e = { af 71 [2] 8b 7f [2] a0 53 [2] 8e 71 [2] 9a 6a [2] 95 70 [2] 8b 6d [2] 89 6c [2] 92 6a [2] 8e 6d [2] 92 42 }

  condition:
    any of them
}