rule TTP_XOR_WriteProcessMemory_a6bd {
  strings:
    $key_a6bd = { f1 cf [2] c3 ed [2] c5 d8 [2] eb d8 [2] d4 c4 }

  condition:
    any of them
}