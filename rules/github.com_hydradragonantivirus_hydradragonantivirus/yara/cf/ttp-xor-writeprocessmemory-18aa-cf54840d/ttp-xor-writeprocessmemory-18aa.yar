rule TTP_XOR_WriteProcessMemory_18aa {
  strings:
    $key_18aa = { 4f d8 [2] 7d fa [2] 7b cf [2] 55 cf [2] 6a d3 }

  condition:
    any of them
}