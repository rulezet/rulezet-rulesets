rule TTP_XOR_QUAD_CurrentVersionRun_23dd {
  strings:
    $key_23dd = { 70 b2 [2] 54 bc [2] 7f 90 [2] 51 b2 [2] 45 a9 [2] 4a b3 [2] 54 ae [2] 56 af [2] 4d a9 [2] 51 ae [2] 4d 81 }

  condition:
    any of them
}