rule TTP_XOR_WriteProcessMemory_2faa {
  strings:
    $key_2faa = { 78 d8 [2] 4a fa [2] 4c cf [2] 62 cf [2] 5d d3 }

  condition:
    any of them
}