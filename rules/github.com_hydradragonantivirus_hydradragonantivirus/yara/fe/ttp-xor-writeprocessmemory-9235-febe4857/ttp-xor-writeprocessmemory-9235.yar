rule TTP_XOR_WriteProcessMemory_9235 {
  strings:
    $key_9235 = { c5 47 [2] f7 65 [2] f1 50 [2] df 50 [2] e0 4c }

  condition:
    any of them
}