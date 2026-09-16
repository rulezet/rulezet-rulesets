rule TTP_XOR_WriteProcessMemory_6e55 {
  strings:
    $key_6e55 = { 39 27 [2] 0b 05 [2] 0d 30 [2] 23 30 [2] 1c 2c }

  condition:
    any of them
}