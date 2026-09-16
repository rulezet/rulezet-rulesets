rule TTP_XOR_WriteProcessMemory_9426 {
  strings:
    $key_9426 = { c3 54 [2] f1 76 [2] f7 43 [2] d9 43 [2] e6 5f }

  condition:
    any of them
}