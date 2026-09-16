rule TTP_XOR_WriteProcessMemory_e4bd {
  strings:
    $key_e4bd = { b3 cf [2] 81 ed [2] 87 d8 [2] a9 d8 [2] 96 c4 }

  condition:
    any of them
}