rule TTP_XOR_WriteProcessMemory_9473 {
  strings:
    $key_9473 = { c3 01 [2] f1 23 [2] f7 16 [2] d9 16 [2] e6 0a }

  condition:
    any of them
}