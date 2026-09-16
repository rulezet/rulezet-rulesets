rule TTP_XOR_QUAD_CurrentVersionRun_eb82 {
  strings:
    $key_eb82 = { b8 ed [2] 9c e3 [2] b7 cf [2] 99 ed [2] 8d f6 [2] 82 ec [2] 9c f1 [2] 9e f0 [2] 85 f6 [2] 99 f1 [2] 85 de }

  condition:
    any of them
}