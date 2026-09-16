rule TTP_XOR_WriteProcessMemory_5daa {
  strings:
    $key_5daa = { 0a d8 [2] 38 fa [2] 3e cf [2] 10 cf [2] 2f d3 }

  condition:
    any of them
}