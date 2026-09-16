rule TTP_XOR_QUAD_CurrentVersionRun_bc12 {
  strings:
    $key_bc12 = { ef 7d [2] cb 73 [2] e0 5f [2] ce 7d [2] da 66 [2] d5 7c [2] cb 61 [2] c9 60 [2] d2 66 [2] ce 61 [2] d2 4e }

  condition:
    any of them
}