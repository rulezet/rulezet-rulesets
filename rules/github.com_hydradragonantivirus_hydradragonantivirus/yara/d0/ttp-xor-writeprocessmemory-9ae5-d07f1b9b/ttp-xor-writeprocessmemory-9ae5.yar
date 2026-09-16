rule TTP_XOR_WriteProcessMemory_9ae5 {
  strings:
    $key_9ae5 = { cd 97 [2] ff b5 [2] f9 80 [2] d7 80 [2] e8 9c }

  condition:
    any of them
}