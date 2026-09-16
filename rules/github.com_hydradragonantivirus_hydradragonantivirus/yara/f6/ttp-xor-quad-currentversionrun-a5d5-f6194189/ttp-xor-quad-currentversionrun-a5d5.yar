rule TTP_XOR_QUAD_CurrentVersionRun_a5d5 {
  strings:
    $key_a5d5 = { f6 ba [2] d2 b4 [2] f9 98 [2] d7 ba [2] c3 a1 [2] cc bb [2] d2 a6 [2] d0 a7 [2] cb a1 [2] d7 a6 [2] cb 89 }

  condition:
    any of them
}