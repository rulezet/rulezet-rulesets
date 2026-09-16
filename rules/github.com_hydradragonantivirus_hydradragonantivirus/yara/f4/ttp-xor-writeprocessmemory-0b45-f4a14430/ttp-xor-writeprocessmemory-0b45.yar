rule TTP_XOR_WriteProcessMemory_0b45 {
  strings:
    $key_0b45 = { 5c 37 [2] 6e 15 [2] 68 20 [2] 46 20 [2] 79 3c }

  condition:
    any of them
}