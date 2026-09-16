rule TTP_XOR_WriteProcessMemory_0faa {
  strings:
    $key_0faa = { 58 d8 [2] 6a fa [2] 6c cf [2] 42 cf [2] 7d d3 }

  condition:
    any of them
}