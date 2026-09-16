rule TTP_XOR_QUAD_CurrentVersionRun_a2d0 {
  strings:
    $key_a2d0 = { f1 bf [2] d5 b1 [2] fe 9d [2] d0 bf [2] c4 a4 [2] cb be [2] d5 a3 [2] d7 a2 [2] cc a4 [2] d0 a3 [2] cc 8c }

  condition:
    any of them
}