rule TTP_XOR_WriteProcessMemory_11aa {
  strings:
    $key_11aa = { 46 d8 [2] 74 fa [2] 72 cf [2] 5c cf [2] 63 d3 }

  condition:
    any of them
}