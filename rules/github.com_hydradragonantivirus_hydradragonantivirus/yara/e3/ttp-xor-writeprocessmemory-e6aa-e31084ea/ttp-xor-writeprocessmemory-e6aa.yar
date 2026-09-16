rule TTP_XOR_WriteProcessMemory_e6aa {
  strings:
    $key_e6aa = { b1 d8 [2] 83 fa [2] 85 cf [2] ab cf [2] 94 d3 }

  condition:
    any of them
}