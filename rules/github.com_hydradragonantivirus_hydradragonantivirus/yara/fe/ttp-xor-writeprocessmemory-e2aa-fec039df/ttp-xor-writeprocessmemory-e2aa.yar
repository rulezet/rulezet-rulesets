rule TTP_XOR_WriteProcessMemory_e2aa {
  strings:
    $key_e2aa = { b5 d8 [2] 87 fa [2] 81 cf [2] af cf [2] 90 d3 }

  condition:
    any of them
}