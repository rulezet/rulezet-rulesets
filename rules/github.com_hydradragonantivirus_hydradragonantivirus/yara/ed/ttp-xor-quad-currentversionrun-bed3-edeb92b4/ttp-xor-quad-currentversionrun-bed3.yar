rule TTP_XOR_QUAD_CurrentVersionRun_bed3 {
  strings:
    $key_bed3 = { ed bc [2] c9 b2 [2] e2 9e [2] cc bc [2] d8 a7 [2] d7 bd [2] c9 a0 [2] cb a1 [2] d0 a7 [2] cc a0 [2] d0 8f }

  condition:
    any of them
}