rule TTP_XOR_QUAD_CurrentVersionRun_beda {
  strings:
    $key_beda = { ed b5 [2] c9 bb [2] e2 97 [2] cc b5 [2] d8 ae [2] d7 b4 [2] c9 a9 [2] cb a8 [2] d0 ae [2] cc a9 [2] d0 86 }

  condition:
    any of them
}