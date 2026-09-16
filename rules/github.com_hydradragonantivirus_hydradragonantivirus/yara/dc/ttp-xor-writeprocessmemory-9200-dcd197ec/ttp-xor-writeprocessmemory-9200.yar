rule TTP_XOR_WriteProcessMemory_9200 {
  strings:
    $key_9200 = { c5 72 [2] f7 50 [2] f1 65 [2] df 65 [2] e0 79 }

  condition:
    any of them
}