rule TTP_XOR_WriteProcessMemory_7f25 {
  strings:
    $key_7f25 = { 28 57 [2] 1a 75 [2] 1c 40 [2] 32 40 [2] 0d 5c }

  condition:
    any of them
}