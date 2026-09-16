rule TTP_XOR_WriteProcessMemory_65aa {
  strings:
    $key_65aa = { 32 d8 [2] 00 fa [2] 06 cf [2] 28 cf [2] 17 d3 }

  condition:
    any of them
}