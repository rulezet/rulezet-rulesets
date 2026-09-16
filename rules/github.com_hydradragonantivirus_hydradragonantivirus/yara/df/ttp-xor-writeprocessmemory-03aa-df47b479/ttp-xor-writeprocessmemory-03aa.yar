rule TTP_XOR_WriteProcessMemory_03aa {
  strings:
    $key_03aa = { 54 d8 [2] 66 fa [2] 60 cf [2] 4e cf [2] 71 d3 }

  condition:
    any of them
}