rule TTP_XOR_QUAD_CurrentVersionRun_b0dd {
  strings:
    $key_b0dd = { e3 b2 [2] c7 bc [2] ec 90 [2] c2 b2 [2] d6 a9 [2] d9 b3 [2] c7 ae [2] c5 af [2] de a9 [2] c2 ae [2] de 81 }

  condition:
    any of them
}