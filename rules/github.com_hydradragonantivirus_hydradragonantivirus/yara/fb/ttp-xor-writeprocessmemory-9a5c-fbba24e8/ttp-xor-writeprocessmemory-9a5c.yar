rule TTP_XOR_WriteProcessMemory_9a5c {
  strings:
    $key_9a5c = { cd 2e [2] ff 0c [2] f9 39 [2] d7 39 [2] e8 25 }

  condition:
    any of them
}