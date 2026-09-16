rule TTP_XOR_WriteProcessMemory_4baa {
  strings:
    $key_4baa = { 1c d8 [2] 2e fa [2] 28 cf [2] 06 cf [2] 39 d3 }

  condition:
    any of them
}