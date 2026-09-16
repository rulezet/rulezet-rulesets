rule TTP_XOR_WriteProcessMemory_9aaa {
  strings:
    $key_9aaa = { cd d8 [2] ff fa [2] f9 cf [2] d7 cf [2] e8 d3 }

  condition:
    any of them
}