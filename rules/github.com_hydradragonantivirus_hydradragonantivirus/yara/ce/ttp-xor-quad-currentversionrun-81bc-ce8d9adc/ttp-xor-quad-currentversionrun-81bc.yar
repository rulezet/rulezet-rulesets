rule TTP_XOR_QUAD_CurrentVersionRun_81bc {
  strings:
    $key_81bc = { d2 d3 [2] f6 dd [2] dd f1 [2] f3 d3 [2] e7 c8 [2] e8 d2 [2] f6 cf [2] f4 ce [2] ef c8 [2] f3 cf [2] ef e0 }

  condition:
    any of them
}