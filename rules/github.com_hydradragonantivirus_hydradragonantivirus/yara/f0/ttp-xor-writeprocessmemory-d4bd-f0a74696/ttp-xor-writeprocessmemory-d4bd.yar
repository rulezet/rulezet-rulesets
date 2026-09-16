rule TTP_XOR_WriteProcessMemory_d4bd {
  strings:
    $key_d4bd = { 83 cf [2] b1 ed [2] b7 d8 [2] 99 d8 [2] a6 c4 }

  condition:
    any of them
}