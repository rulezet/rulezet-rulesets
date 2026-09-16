rule TTP_XOR_WriteProcessMemory_9a56 {
  strings:
    $key_9a56 = { cd 24 [2] ff 06 [2] f9 33 [2] d7 33 [2] e8 2f }

  condition:
    any of them
}