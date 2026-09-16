rule TTP_XOR_QUAD_CurrentVersionRun_bc7a {
  strings:
    $key_bc7a = { ef 15 [2] cb 1b [2] e0 37 [2] ce 15 [2] da 0e [2] d5 14 [2] cb 09 [2] c9 08 [2] d2 0e [2] ce 09 [2] d2 26 }

  condition:
    any of them
}