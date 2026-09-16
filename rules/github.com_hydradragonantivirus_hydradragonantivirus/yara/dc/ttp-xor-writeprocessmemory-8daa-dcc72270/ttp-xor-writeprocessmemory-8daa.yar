rule TTP_XOR_WriteProcessMemory_8daa {
  strings:
    $key_8daa = { da d8 [2] e8 fa [2] ee cf [2] c0 cf [2] ff d3 }

  condition:
    any of them
}