rule TTP_XOR_QUAD_CurrentVersionRun_f1dd {
  strings:
    $key_f1dd = { a2 b2 [2] 86 bc [2] ad 90 [2] 83 b2 [2] 97 a9 [2] 98 b3 [2] 86 ae [2] 84 af [2] 9f a9 [2] 83 ae [2] 9f 81 }

  condition:
    any of them
}