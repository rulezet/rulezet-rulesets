rule TTP_XOR_QUAD_CurrentVersionRun_bedb {
  strings:
    $key_bedb = { ed b4 [2] c9 ba [2] e2 96 [2] cc b4 [2] d8 af [2] d7 b5 [2] c9 a8 [2] cb a9 [2] d0 af [2] cc a8 [2] d0 87 }

  condition:
    any of them
}