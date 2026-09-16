rule TTP_XOR_WriteProcessMemory_a7aa {
  strings:
    $key_a7aa = { f0 d8 [2] c2 fa [2] c4 cf [2] ea cf [2] d5 d3 }

  condition:
    any of them
}