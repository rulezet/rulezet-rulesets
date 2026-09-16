rule TTP_XOR_WriteProcessMemory_e5aa {
  strings:
    $key_e5aa = { b2 d8 [2] 80 fa [2] 86 cf [2] a8 cf [2] 97 d3 }

  condition:
    any of them
}