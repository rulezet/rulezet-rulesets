rule TTP_XOR_WriteProcessMemory_16aa {
  strings:
    $key_16aa = { 41 d8 [2] 73 fa [2] 75 cf [2] 5b cf [2] 64 d3 }

  condition:
    any of them
}