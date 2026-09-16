rule TTP_XOR_QUAD_CurrentVersionRun_e4dd {
  strings:
    $key_e4dd = { b7 b2 [2] 93 bc [2] b8 90 [2] 96 b2 [2] 82 a9 [2] 8d b3 [2] 93 ae [2] 91 af [2] 8a a9 [2] 96 ae [2] 8a 81 }

  condition:
    any of them
}