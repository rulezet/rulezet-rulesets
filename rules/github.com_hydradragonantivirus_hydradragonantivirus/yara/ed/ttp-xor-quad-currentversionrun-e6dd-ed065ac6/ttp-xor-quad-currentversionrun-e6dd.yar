rule TTP_XOR_QUAD_CurrentVersionRun_e6dd {
  strings:
    $key_e6dd = { b5 b2 [2] 91 bc [2] ba 90 [2] 94 b2 [2] 80 a9 [2] 8f b3 [2] 91 ae [2] 93 af [2] 88 a9 [2] 94 ae [2] 88 81 }

  condition:
    any of them
}