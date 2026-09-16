rule TTP_XOR_WriteProcessMemory_9427 {
  strings:
    $key_9427 = { c3 55 [2] f1 77 [2] f7 42 [2] d9 42 [2] e6 5e }

  condition:
    any of them
}