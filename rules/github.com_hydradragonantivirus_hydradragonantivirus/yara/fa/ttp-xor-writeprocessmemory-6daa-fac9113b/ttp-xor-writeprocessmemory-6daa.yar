rule TTP_XOR_WriteProcessMemory_6daa {
  strings:
    $key_6daa = { 3a d8 [2] 08 fa [2] 0e cf [2] 20 cf [2] 1f d3 }

  condition:
    any of them
}