rule TTP_XOR_WriteProcessMemory_5eaa {
  strings:
    $key_5eaa = { 09 d8 [2] 3b fa [2] 3d cf [2] 13 cf [2] 2c d3 }

  condition:
    any of them
}