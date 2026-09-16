rule TTP_XOR_WriteProcessMemory_f6aa {
  strings:
    $key_f6aa = { a1 d8 [2] 93 fa [2] 95 cf [2] bb cf [2] 84 d3 }

  condition:
    any of them
}