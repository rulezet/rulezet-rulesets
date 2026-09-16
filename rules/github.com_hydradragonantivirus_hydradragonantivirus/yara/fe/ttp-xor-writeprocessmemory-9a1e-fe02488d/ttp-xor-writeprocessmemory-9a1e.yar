rule TTP_XOR_WriteProcessMemory_9a1e {
  strings:
    $key_9a1e = { cd 6c [2] ff 4e [2] f9 7b [2] d7 7b [2] e8 67 }

  condition:
    any of them
}