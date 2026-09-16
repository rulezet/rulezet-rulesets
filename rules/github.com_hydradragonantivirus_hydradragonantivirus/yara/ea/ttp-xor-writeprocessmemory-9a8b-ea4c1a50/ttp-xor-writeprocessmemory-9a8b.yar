rule TTP_XOR_WriteProcessMemory_9a8b {
  strings:
    $key_9a8b = { cd f9 [2] ff db [2] f9 ee [2] d7 ee [2] e8 f2 }

  condition:
    any of them
}