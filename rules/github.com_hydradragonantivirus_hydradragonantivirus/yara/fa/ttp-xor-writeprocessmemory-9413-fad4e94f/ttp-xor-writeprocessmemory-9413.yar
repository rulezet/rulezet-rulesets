rule TTP_XOR_WriteProcessMemory_9413 {
  strings:
    $key_9413 = { c3 61 [2] f1 43 [2] f7 76 [2] d9 76 [2] e6 6a }

  condition:
    any of them
}