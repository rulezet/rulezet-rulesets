rule TTP_XOR_WriteProcessMemory_6e45 {
  strings:
    $key_6e45 = { 39 37 [2] 0b 15 [2] 0d 20 [2] 23 20 [2] 1c 3c }

  condition:
    any of them
}