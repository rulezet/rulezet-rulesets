rule TTP_XOR_QUAD_CurrentVersionRun_e1dd {
  strings:
    $key_e1dd = { b2 b2 [2] 96 bc [2] bd 90 [2] 93 b2 [2] 87 a9 [2] 88 b3 [2] 96 ae [2] 94 af [2] 8f a9 [2] 93 ae [2] 8f 81 }

  condition:
    any of them
}