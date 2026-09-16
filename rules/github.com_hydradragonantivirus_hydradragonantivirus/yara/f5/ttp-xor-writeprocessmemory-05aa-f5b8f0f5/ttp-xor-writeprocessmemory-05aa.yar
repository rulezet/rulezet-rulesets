rule TTP_XOR_WriteProcessMemory_05aa {
  strings:
    $key_05aa = { 52 d8 [2] 60 fa [2] 66 cf [2] 48 cf [2] 77 d3 }

  condition:
    any of them
}