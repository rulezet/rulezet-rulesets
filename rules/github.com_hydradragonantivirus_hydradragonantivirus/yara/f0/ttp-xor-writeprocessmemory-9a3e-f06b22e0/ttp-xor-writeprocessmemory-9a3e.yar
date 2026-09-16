rule TTP_XOR_WriteProcessMemory_9a3e {
  strings:
    $key_9a3e = { cd 4c [2] ff 6e [2] f9 5b [2] d7 5b [2] e8 47 }

  condition:
    any of them
}