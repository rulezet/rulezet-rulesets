rule TTP_XOR_WriteProcessMemory_ecaa {
  strings:
    $key_ecaa = { bb d8 [2] 89 fa [2] 8f cf [2] a1 cf [2] 9e d3 }

  condition:
    any of them
}