rule TTP_XOR_QUAD_CurrentVersionRun_ec7f {
  strings:
    $key_ec7f = { bf 10 [2] 9b 1e [2] b0 32 [2] 9e 10 [2] 8a 0b [2] 85 11 [2] 9b 0c [2] 99 0d [2] 82 0b [2] 9e 0c [2] 82 23 }

  condition:
    any of them
}