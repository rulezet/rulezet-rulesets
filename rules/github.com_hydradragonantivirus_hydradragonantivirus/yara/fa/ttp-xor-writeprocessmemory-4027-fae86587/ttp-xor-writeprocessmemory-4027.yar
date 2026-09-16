rule TTP_XOR_WriteProcessMemory_4027 {
  strings:
    $key_4027 = { 17 55 [2] 25 77 [2] 23 42 [2] 0d 42 [2] 32 5e }

  condition:
    any of them
}