rule TTP_XOR_WriteProcessMemory_d5bd {
  strings:
    $key_d5bd = { 82 cf [2] b0 ed [2] b6 d8 [2] 98 d8 [2] a7 c4 }

  condition:
    any of them
}