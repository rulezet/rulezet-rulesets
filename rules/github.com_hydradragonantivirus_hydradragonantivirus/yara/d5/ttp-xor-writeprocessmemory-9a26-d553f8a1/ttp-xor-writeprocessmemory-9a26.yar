rule TTP_XOR_WriteProcessMemory_9a26 {
  strings:
    $key_9a26 = { cd 54 [2] ff 76 [2] f9 43 [2] d7 43 [2] e8 5f }

  condition:
    any of them
}