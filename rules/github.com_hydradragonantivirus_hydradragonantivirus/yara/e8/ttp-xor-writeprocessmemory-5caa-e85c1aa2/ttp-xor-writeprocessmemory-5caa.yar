rule TTP_XOR_WriteProcessMemory_5caa {
  strings:
    $key_5caa = { 0b d8 [2] 39 fa [2] 3f cf [2] 11 cf [2] 2e d3 }

  condition:
    any of them
}