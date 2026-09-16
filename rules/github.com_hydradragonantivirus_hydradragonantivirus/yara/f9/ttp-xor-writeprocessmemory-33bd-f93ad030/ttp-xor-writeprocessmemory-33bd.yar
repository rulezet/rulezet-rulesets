rule TTP_XOR_WriteProcessMemory_33bd {
  strings:
    $key_33bd = { 64 cf [2] 56 ed [2] 50 d8 [2] 7e d8 [2] 41 c4 }

  condition:
    any of them
}