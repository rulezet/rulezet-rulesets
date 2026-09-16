rule TTP_XOR_WriteProcessMemory_0fbd {
  strings:
    $key_0fbd = { 58 cf [2] 6a ed [2] 6c d8 [2] 42 d8 [2] 7d c4 }

  condition:
    any of them
}