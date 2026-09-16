rule TTP_XOR_WriteProcessMemory_9a25 {
  strings:
    $key_9a25 = { cd 57 [2] ff 75 [2] f9 40 [2] d7 40 [2] e8 5c }

  condition:
    any of them
}