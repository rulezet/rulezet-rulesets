rule TTP_XOR_WriteProcessMemory_9a3b {
  strings:
    $key_9a3b = { cd 49 [2] ff 6b [2] f9 5e [2] d7 5e [2] e8 42 }

  condition:
    any of them
}