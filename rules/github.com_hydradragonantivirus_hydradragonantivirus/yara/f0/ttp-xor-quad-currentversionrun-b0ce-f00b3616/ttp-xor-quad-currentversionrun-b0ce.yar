rule TTP_XOR_QUAD_CurrentVersionRun_b0ce {
  strings:
    $key_b0ce = { e3 a1 [2] c7 af [2] ec 83 [2] c2 a1 [2] d6 ba [2] d9 a0 [2] c7 bd [2] c5 bc [2] de ba [2] c2 bd [2] de 92 }

  condition:
    any of them
}