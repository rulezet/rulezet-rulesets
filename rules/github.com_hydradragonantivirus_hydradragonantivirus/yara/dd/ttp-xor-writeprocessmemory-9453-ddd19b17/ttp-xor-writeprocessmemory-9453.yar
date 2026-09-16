rule TTP_XOR_WriteProcessMemory_9453 {
  strings:
    $key_9453 = { c3 21 [2] f1 03 [2] f7 36 [2] d9 36 [2] e6 2a }

  condition:
    any of them
}