rule TTP_XOR_QUAD_CurrentVersionRun_bc7d {
  strings:
    $key_bc7d = { ef 12 [2] cb 1c [2] e0 30 [2] ce 12 [2] da 09 [2] d5 13 [2] cb 0e [2] c9 0f [2] d2 09 [2] ce 0e [2] d2 21 }

  condition:
    any of them
}