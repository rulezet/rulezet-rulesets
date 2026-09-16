rule TTP_XOR_WriteProcessMemory_f5aa {
  strings:
    $key_f5aa = { a2 d8 [2] 90 fa [2] 96 cf [2] b8 cf [2] 87 d3 }

  condition:
    any of them
}