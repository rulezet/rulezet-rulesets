rule TTP_XOR_WriteProcessMemory_f7bd {
  strings:
    $key_f7bd = { a0 cf [2] 92 ed [2] 94 d8 [2] ba d8 [2] 85 c4 }

  condition:
    any of them
}