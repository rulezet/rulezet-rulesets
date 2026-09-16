rule TTP_XOR_WriteProcessMemory_b0aa {
  strings:
    $key_b0aa = { e7 d8 [2] d5 fa [2] d3 cf [2] fd cf [2] c2 d3 }

  condition:
    any of them
}