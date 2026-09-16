rule TTP_XOR_WriteProcessMemory_9ae9 {
  strings:
    $key_9ae9 = { cd 9b [2] ff b9 [2] f9 8c [2] d7 8c [2] e8 90 }

  condition:
    any of them
}