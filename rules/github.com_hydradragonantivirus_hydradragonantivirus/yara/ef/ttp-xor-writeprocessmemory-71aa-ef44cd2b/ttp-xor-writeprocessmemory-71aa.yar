rule TTP_XOR_WriteProcessMemory_71aa {
  strings:
    $key_71aa = { 26 d8 [2] 14 fa [2] 12 cf [2] 3c cf [2] 03 d3 }

  condition:
    any of them
}