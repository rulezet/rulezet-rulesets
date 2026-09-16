rule TTP_XOR_WriteProcessMemory_73aa {
  strings:
    $key_73aa = { 24 d8 [2] 16 fa [2] 10 cf [2] 3e cf [2] 01 d3 }

  condition:
    any of them
}