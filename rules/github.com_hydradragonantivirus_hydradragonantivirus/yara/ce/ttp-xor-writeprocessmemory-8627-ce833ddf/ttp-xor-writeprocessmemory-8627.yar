rule TTP_XOR_WriteProcessMemory_8627 {
  strings:
    $key_8627 = { d1 55 [2] e3 77 [2] e5 42 [2] cb 42 [2] f4 5e }

  condition:
    any of them
}