rule TTP_XOR_WriteProcessMemory_88bd {
  strings:
    $key_88bd = { df cf [2] ed ed [2] eb d8 [2] c5 d8 [2] fa c4 }

  condition:
    any of them
}