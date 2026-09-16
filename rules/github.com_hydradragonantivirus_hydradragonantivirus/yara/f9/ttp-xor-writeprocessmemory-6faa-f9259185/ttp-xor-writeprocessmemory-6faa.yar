rule TTP_XOR_WriteProcessMemory_6faa {
  strings:
    $key_6faa = { 38 d8 [2] 0a fa [2] 0c cf [2] 22 cf [2] 1d d3 }

  condition:
    any of them
}