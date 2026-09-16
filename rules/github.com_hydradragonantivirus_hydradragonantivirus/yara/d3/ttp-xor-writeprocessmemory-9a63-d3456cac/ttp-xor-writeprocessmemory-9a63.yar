rule TTP_XOR_WriteProcessMemory_9a63 {
  strings:
    $key_9a63 = { cd 11 [2] ff 33 [2] f9 06 [2] d7 06 [2] e8 1a }

  condition:
    any of them
}