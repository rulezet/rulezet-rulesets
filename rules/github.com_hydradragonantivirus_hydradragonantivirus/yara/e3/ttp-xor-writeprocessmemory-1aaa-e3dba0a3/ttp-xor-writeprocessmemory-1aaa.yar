rule TTP_XOR_WriteProcessMemory_1aaa {
  strings:
    $key_1aaa = { 4d d8 [2] 7f fa [2] 79 cf [2] 57 cf [2] 68 d3 }

  condition:
    any of them
}