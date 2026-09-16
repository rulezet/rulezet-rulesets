rule TTP_XOR_WriteProcessMemory_2baa {
  strings:
    $key_2baa = { 7c d8 [2] 4e fa [2] 48 cf [2] 66 cf [2] 59 d3 }

  condition:
    any of them
}