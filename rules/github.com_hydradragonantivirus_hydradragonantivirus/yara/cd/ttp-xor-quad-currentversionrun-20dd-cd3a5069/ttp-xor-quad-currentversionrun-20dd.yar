rule TTP_XOR_QUAD_CurrentVersionRun_20dd {
  strings:
    $key_20dd = { 73 b2 [2] 57 bc [2] 7c 90 [2] 52 b2 [2] 46 a9 [2] 49 b3 [2] 57 ae [2] 55 af [2] 4e a9 [2] 52 ae [2] 4e 81 }

  condition:
    any of them
}