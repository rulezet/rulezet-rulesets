rule TTP_XOR_WriteProcessMemory_13aa {
  strings:
    $key_13aa = { 44 d8 [2] 76 fa [2] 70 cf [2] 5e cf [2] 61 d3 }

  condition:
    any of them
}