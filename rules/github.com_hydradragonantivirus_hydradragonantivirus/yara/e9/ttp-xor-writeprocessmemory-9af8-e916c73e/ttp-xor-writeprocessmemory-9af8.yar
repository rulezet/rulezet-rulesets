rule TTP_XOR_WriteProcessMemory_9af8 {
  strings:
    $key_9af8 = { cd 8a [2] ff a8 [2] f9 9d [2] d7 9d [2] e8 81 }

  condition:
    any of them
}