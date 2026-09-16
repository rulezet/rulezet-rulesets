rule TTP_XOR_WriteProcessMemory_69aa {
  strings:
    $key_69aa = { 3e d8 [2] 0c fa [2] 0a cf [2] 24 cf [2] 1b d3 }

  condition:
    any of them
}