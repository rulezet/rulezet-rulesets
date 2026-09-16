rule TTP_XOR_QUAD_CurrentVersionRun_bec9 {
  strings:
    $key_bec9 = { ed a6 [2] c9 a8 [2] e2 84 [2] cc a6 [2] d8 bd [2] d7 a7 [2] c9 ba [2] cb bb [2] d0 bd [2] cc ba [2] d0 95 }

  condition:
    any of them
}