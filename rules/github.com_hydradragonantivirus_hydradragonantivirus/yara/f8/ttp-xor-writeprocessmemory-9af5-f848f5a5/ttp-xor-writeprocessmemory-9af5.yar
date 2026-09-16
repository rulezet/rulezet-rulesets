rule TTP_XOR_WriteProcessMemory_9af5 {
  strings:
    $key_9af5 = { cd 87 [2] ff a5 [2] f9 90 [2] d7 90 [2] e8 8c }

  condition:
    any of them
}