rule TTP_XOR_QUAD_CurrentVersionRun_bed4 {
  strings:
    $key_bed4 = { ed bb [2] c9 b5 [2] e2 99 [2] cc bb [2] d8 a0 [2] d7 ba [2] c9 a7 [2] cb a6 [2] d0 a0 [2] cc a7 [2] d0 88 }

  condition:
    any of them
}