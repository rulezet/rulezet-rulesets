rule TTP_XOR_WriteProcessMemory_c4aa {
  strings:
    $key_c4aa = { 93 d8 [2] a1 fa [2] a7 cf [2] 89 cf [2] b6 d3 }

  condition:
    any of them
}