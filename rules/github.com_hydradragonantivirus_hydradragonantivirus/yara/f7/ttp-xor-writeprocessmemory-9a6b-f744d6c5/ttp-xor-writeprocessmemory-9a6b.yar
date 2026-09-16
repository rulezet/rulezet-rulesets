rule TTP_XOR_WriteProcessMemory_9a6b {
  strings:
    $key_9a6b = { cd 19 [2] ff 3b [2] f9 0e [2] d7 0e [2] e8 12 }

  condition:
    any of them
}