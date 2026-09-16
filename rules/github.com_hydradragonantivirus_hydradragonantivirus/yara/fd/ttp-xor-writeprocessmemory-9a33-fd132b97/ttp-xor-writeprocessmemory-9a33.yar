rule TTP_XOR_WriteProcessMemory_9a33 {
  strings:
    $key_9a33 = { cd 41 [2] ff 63 [2] f9 56 [2] d7 56 [2] e8 4a }

  condition:
    any of them
}