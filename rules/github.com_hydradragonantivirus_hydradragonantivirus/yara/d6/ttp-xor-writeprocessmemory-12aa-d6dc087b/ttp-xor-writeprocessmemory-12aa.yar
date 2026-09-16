rule TTP_XOR_WriteProcessMemory_12aa {
  strings:
    $key_12aa = { 45 d8 [2] 77 fa [2] 71 cf [2] 5f cf [2] 60 d3 }

  condition:
    any of them
}