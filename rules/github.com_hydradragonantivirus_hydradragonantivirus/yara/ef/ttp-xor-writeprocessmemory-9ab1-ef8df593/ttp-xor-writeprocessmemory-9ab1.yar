rule TTP_XOR_WriteProcessMemory_9ab1 {
  strings:
    $key_9ab1 = { cd c3 [2] ff e1 [2] f9 d4 [2] d7 d4 [2] e8 c8 }

  condition:
    any of them
}