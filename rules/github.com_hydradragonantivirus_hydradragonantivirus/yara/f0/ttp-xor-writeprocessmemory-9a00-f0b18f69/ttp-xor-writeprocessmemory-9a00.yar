rule TTP_XOR_WriteProcessMemory_9a00 {
  strings:
    $key_9a00 = { cd 72 [2] ff 50 [2] f9 65 [2] d7 65 [2] e8 79 }

  condition:
    any of them
}