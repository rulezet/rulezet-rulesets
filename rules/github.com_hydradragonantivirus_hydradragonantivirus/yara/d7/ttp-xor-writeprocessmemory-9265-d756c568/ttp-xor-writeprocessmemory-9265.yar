rule TTP_XOR_WriteProcessMemory_9265 {
  strings:
    $key_9265 = { c5 17 [2] f7 35 [2] f1 00 [2] df 00 [2] e0 1c }

  condition:
    any of them
}