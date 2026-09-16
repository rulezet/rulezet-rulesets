rule TTP_XOR_QUAD_CurrentVersionRun_b083 {
  strings:
    $key_b083 = { e3 ec [2] c7 e2 [2] ec ce [2] c2 ec [2] d6 f7 [2] d9 ed [2] c7 f0 [2] c5 f1 [2] de f7 [2] c2 f0 [2] de df }

  condition:
    any of them
}