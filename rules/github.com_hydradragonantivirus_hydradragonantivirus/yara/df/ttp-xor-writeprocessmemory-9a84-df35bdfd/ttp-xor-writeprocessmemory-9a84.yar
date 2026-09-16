rule TTP_XOR_WriteProcessMemory_9a84 {
  strings:
    $key_9a84 = { cd f6 [2] ff d4 [2] f9 e1 [2] d7 e1 [2] e8 fd }

  condition:
    any of them
}