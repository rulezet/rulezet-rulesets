rule TTP_XOR_WriteProcessMemory_2daa {
  strings:
    $key_2daa = { 7a d8 [2] 48 fa [2] 4e cf [2] 60 cf [2] 5f d3 }

  condition:
    any of them
}