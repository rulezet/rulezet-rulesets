rule TTP_XOR_WriteProcessMemory_57aa {
  strings:
    $key_57aa = { 00 d8 [2] 32 fa [2] 34 cf [2] 1a cf [2] 25 d3 }

  condition:
    any of them
}