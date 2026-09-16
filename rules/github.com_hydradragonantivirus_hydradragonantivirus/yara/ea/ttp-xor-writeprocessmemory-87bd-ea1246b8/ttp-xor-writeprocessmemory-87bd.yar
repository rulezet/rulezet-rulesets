rule TTP_XOR_WriteProcessMemory_87bd {
  strings:
    $key_87bd = { d0 cf [2] e2 ed [2] e4 d8 [2] ca d8 [2] f5 c4 }

  condition:
    any of them
}