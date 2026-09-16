rule TTP_XOR_WriteProcessMemory_9527 {
  strings:
    $key_9527 = { c2 55 [2] f0 77 [2] f6 42 [2] d8 42 [2] e7 5e }

  condition:
    any of them
}