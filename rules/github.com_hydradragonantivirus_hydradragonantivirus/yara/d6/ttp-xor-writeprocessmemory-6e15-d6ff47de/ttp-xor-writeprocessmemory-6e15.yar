rule TTP_XOR_WriteProcessMemory_6e15 {
  strings:
    $key_6e15 = { 39 67 [2] 0b 45 [2] 0d 70 [2] 23 70 [2] 1c 6c }

  condition:
    any of them
}