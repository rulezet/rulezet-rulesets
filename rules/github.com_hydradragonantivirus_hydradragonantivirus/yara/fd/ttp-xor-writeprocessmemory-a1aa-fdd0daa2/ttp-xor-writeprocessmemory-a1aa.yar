rule TTP_XOR_WriteProcessMemory_a1aa {
  strings:
    $key_a1aa = { f6 d8 [2] c4 fa [2] c2 cf [2] ec cf [2] d3 d3 }

  condition:
    any of them
}