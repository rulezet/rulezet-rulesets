rule TTP_XOR_QUAD_CurrentVersionRun_13dd {
  strings:
    $key_13dd = { 40 b2 [2] 64 bc [2] 4f 90 [2] 61 b2 [2] 75 a9 [2] 7a b3 [2] 64 ae [2] 66 af [2] 7d a9 [2] 61 ae [2] 7d 81 }

  condition:
    any of them
}