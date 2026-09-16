rule TTP_XOR_QUAD_CurrentVersionRun_a5a3 {
  strings:
    $key_a5a3 = { f6 cc [2] d2 c2 [2] f9 ee [2] d7 cc [2] c3 d7 [2] cc cd [2] d2 d0 [2] d0 d1 [2] cb d7 [2] d7 d0 [2] cb ff }

  condition:
    any of them
}