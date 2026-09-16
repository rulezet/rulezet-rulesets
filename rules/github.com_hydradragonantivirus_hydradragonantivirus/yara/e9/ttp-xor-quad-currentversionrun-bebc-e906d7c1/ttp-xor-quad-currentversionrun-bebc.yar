rule TTP_XOR_QUAD_CurrentVersionRun_bebc {
  strings:
    $key_bebc = { ed d3 [2] c9 dd [2] e2 f1 [2] cc d3 [2] d8 c8 [2] d7 d2 [2] c9 cf [2] cb ce [2] d0 c8 [2] cc cf [2] d0 e0 }

  condition:
    any of them
}