rule TTP_XOR_WriteProcessMemory_75aa {
  strings:
    $key_75aa = { 22 d8 [2] 10 fa [2] 16 cf [2] 38 cf [2] 07 d3 }

  condition:
    any of them
}