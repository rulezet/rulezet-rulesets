rule TTP_XOR_WriteProcessMemory_7caa {
  strings:
    $key_7caa = { 2b d8 [2] 19 fa [2] 1f cf [2] 31 cf [2] 0e d3 }

  condition:
    any of them
}