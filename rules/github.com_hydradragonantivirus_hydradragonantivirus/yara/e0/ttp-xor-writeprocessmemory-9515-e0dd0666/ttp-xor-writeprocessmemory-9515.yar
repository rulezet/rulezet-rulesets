rule TTP_XOR_WriteProcessMemory_9515 {
  strings:
    $key_9515 = { c2 67 [2] f0 45 [2] f6 70 [2] d8 70 [2] e7 6c }

  condition:
    any of them
}