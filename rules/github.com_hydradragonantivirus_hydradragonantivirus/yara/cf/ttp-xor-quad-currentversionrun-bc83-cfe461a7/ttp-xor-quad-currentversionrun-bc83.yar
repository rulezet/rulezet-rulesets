rule TTP_XOR_QUAD_CurrentVersionRun_bc83 {
  strings:
    $key_bc83 = { ef ec [2] cb e2 [2] e0 ce [2] ce ec [2] da f7 [2] d5 ed [2] cb f0 [2] c9 f1 [2] d2 f7 [2] ce f0 [2] d2 df }

  condition:
    any of them
}