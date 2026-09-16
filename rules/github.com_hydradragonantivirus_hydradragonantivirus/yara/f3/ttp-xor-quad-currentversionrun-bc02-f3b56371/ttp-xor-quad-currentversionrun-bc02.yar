rule TTP_XOR_QUAD_CurrentVersionRun_bc02 {
  strings:
    $key_bc02 = { ef 6d [2] cb 63 [2] e0 4f [2] ce 6d [2] da 76 [2] d5 6c [2] cb 71 [2] c9 70 [2] d2 76 [2] ce 71 [2] d2 5e }

  condition:
    any of them
}