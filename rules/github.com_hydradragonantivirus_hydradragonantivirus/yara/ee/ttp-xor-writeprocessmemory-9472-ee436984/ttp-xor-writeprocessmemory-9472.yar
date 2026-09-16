rule TTP_XOR_WriteProcessMemory_9472 {
  strings:
    $key_9472 = { c3 00 [2] f1 22 [2] f7 17 [2] d9 17 [2] e6 0b }

  condition:
    any of them
}