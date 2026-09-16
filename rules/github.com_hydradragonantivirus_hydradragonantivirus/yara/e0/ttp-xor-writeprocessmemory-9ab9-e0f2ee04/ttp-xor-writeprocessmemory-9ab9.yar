rule TTP_XOR_WriteProcessMemory_9ab9 {
  strings:
    $key_9ab9 = { cd cb [2] ff e9 [2] f9 dc [2] d7 dc [2] e8 c0 }

  condition:
    any of them
}