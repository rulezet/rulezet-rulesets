rule TTP_XOR_QUAD_CurrentVersionRun_bce3 {
  strings:
    $key_bce3 = { ef 8c [2] cb 82 [2] e0 ae [2] ce 8c [2] da 97 [2] d5 8d [2] cb 90 [2] c9 91 [2] d2 97 [2] ce 90 [2] d2 bf }

  condition:
    any of them
}