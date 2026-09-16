rule TTP_XOR_QUAD_CurrentVersionRun_bc7f {
  strings:
    $key_bc7f = { ef 10 [2] cb 1e [2] e0 32 [2] ce 10 [2] da 0b [2] d5 11 [2] cb 0c [2] c9 0d [2] d2 0b [2] ce 0c [2] d2 23 }

  condition:
    any of them
}