rule TTP_XOR_WriteProcessMemory_9a41 {
  strings:
    $key_9a41 = { cd 33 [2] ff 11 [2] f9 24 [2] d7 24 [2] e8 38 }

  condition:
    any of them
}