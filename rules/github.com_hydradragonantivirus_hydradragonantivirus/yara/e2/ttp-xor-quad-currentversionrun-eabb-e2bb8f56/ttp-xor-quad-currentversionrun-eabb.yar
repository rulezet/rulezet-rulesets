rule TTP_XOR_QUAD_CurrentVersionRun_eabb {
  strings:
    $key_eabb = { b9 d4 [2] 9d da [2] b6 f6 [2] 98 d4 [2] 8c cf [2] 83 d5 [2] 9d c8 [2] 9f c9 [2] 84 cf [2] 98 c8 [2] 84 e7 }

  condition:
    any of them
}