rule TTP_XOR_WriteProcessMemory_c5bd {
  strings:
    $key_c5bd = { 92 cf [2] a0 ed [2] a6 d8 [2] 88 d8 [2] b7 c4 }

  condition:
    any of them
}