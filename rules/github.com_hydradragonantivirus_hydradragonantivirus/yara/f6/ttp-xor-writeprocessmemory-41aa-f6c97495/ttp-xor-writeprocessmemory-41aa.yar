rule TTP_XOR_WriteProcessMemory_41aa {
  strings:
    $key_41aa = { 16 d8 [2] 24 fa [2] 22 cf [2] 0c cf [2] 33 d3 }

  condition:
    any of them
}