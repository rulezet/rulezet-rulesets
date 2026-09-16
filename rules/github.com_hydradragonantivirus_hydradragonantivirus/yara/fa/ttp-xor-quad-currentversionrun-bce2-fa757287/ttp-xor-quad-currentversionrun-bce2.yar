rule TTP_XOR_QUAD_CurrentVersionRun_bce2 {
  strings:
    $key_bce2 = { ef 8d [2] cb 83 [2] e0 af [2] ce 8d [2] da 96 [2] d5 8c [2] cb 91 [2] c9 90 [2] d2 96 [2] ce 91 [2] d2 be }

  condition:
    any of them
}