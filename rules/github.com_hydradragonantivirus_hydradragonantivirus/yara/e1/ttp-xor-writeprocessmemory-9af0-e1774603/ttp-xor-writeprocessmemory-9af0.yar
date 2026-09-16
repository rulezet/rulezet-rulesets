rule TTP_XOR_WriteProcessMemory_9af0 {
  strings:
    $key_9af0 = { cd 82 [2] ff a0 [2] f9 95 [2] d7 95 [2] e8 89 }

  condition:
    any of them
}