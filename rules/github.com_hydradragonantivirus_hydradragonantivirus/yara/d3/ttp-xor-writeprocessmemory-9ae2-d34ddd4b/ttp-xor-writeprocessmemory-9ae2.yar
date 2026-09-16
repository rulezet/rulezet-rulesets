rule TTP_XOR_WriteProcessMemory_9ae2 {
  strings:
    $key_9ae2 = { cd 90 [2] ff b2 [2] f9 87 [2] d7 87 [2] e8 9b }

  condition:
    any of them
}