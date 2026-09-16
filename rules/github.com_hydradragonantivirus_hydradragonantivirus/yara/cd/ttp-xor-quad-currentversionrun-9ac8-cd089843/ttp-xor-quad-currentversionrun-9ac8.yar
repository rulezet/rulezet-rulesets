rule TTP_XOR_QUAD_CurrentVersionRun_9ac8 {
  strings:
    $key_9ac8 = { c9 a7 [2] ed a9 [2] c6 85 [2] e8 a7 [2] fc bc [2] f3 a6 [2] ed bb [2] ef ba [2] f4 bc [2] e8 bb [2] f4 94 }

  condition:
    any of them
}