rule TTP_XOR_WriteProcessMemory_9a0c {
  strings:
    $key_9a0c = { cd 7e [2] ff 5c [2] f9 69 [2] d7 69 [2] e8 75 }

  condition:
    any of them
}