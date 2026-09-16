rule TTP_XOR_WriteProcessMemory_97aa {
  strings:
    $key_97aa = { c0 d8 [2] f2 fa [2] f4 cf [2] da cf [2] e5 d3 }

  condition:
    any of them
}