rule TTP_XOR_QUAD_CurrentVersionRun_b9bb {
  strings:
    $key_b9bb = { ea d4 [2] ce da [2] e5 f6 [2] cb d4 [2] df cf [2] d0 d5 [2] ce c8 [2] cc c9 [2] d7 cf [2] cb c8 [2] d7 e7 }

  condition:
    any of them
}