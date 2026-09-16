rule TTP_XOR_WriteProcessMemory_c1aa {
  strings:
    $key_c1aa = { 96 d8 [2] a4 fa [2] a2 cf [2] 8c cf [2] b3 d3 }

  condition:
    any of them
}