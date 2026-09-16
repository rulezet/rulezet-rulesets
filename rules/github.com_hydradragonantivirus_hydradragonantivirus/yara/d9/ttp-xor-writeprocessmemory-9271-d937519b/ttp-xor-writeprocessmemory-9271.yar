rule TTP_XOR_WriteProcessMemory_9271 {
  strings:
    $key_9271 = { c5 03 [2] f7 21 [2] f1 14 [2] df 14 [2] e0 08 }

  condition:
    any of them
}