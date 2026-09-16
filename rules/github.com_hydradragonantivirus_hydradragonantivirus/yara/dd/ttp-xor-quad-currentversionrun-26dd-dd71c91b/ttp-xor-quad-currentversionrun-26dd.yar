rule TTP_XOR_QUAD_CurrentVersionRun_26dd {
  strings:
    $key_26dd = { 75 b2 [2] 51 bc [2] 7a 90 [2] 54 b2 [2] 40 a9 [2] 4f b3 [2] 51 ae [2] 53 af [2] 48 a9 [2] 54 ae [2] 48 81 }

  condition:
    any of them
}