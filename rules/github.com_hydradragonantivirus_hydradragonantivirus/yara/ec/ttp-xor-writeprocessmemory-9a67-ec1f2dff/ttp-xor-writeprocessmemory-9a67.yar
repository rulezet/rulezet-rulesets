rule TTP_XOR_WriteProcessMemory_9a67 {
  strings:
    $key_9a67 = { cd 15 [2] ff 37 [2] f9 02 [2] d7 02 [2] e8 1e }

  condition:
    any of them
}