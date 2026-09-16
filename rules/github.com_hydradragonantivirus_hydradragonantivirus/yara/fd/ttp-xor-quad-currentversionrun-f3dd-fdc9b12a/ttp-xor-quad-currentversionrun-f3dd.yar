rule TTP_XOR_QUAD_CurrentVersionRun_f3dd {
  strings:
    $key_f3dd = { a0 b2 [2] 84 bc [2] af 90 [2] 81 b2 [2] 95 a9 [2] 9a b3 [2] 84 ae [2] 86 af [2] 9d a9 [2] 81 ae [2] 9d 81 }

  condition:
    any of them
}