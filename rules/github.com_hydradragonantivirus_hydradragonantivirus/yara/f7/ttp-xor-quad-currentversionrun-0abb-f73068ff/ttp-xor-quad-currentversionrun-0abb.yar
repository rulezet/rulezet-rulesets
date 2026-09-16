rule TTP_XOR_QUAD_CurrentVersionRun_0abb {
  strings:
    $key_0abb = { 59 d4 [2] 7d da [2] 56 f6 [2] 78 d4 [2] 6c cf [2] 63 d5 [2] 7d c8 [2] 7f c9 [2] 64 cf [2] 78 c8 [2] 64 e7 }

  condition:
    any of them
}