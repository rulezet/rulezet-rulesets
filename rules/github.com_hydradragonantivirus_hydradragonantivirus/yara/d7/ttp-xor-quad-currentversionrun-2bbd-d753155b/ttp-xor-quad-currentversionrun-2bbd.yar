rule TTP_XOR_QUAD_CurrentVersionRun_2bbd {
  strings:
    $key_2bbd = { 78 d2 [2] 5c dc [2] 77 f0 [2] 59 d2 [2] 4d c9 [2] 42 d3 [2] 5c ce [2] 5e cf [2] 45 c9 [2] 59 ce [2] 45 e1 }

  condition:
    any of them
}