rule TTP_XOR_WriteProcessMemory_6e25 {
  strings:
    $key_6e25 = { 39 57 [2] 0b 75 [2] 0d 40 [2] 23 40 [2] 1c 5c }

  condition:
    any of them
}