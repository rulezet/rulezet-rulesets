rule TTP_XOR_WriteProcessMemory_85aa {
  strings:
    $key_85aa = { d2 d8 [2] e0 fa [2] e6 cf [2] c8 cf [2] f7 d3 }

  condition:
    any of them
}