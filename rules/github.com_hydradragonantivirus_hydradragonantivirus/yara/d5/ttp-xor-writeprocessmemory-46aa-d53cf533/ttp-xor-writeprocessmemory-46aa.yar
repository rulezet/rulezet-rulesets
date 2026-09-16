rule TTP_XOR_WriteProcessMemory_46aa {
  strings:
    $key_46aa = { 11 d8 [2] 23 fa [2] 25 cf [2] 0b cf [2] 34 d3 }

  condition:
    any of them
}