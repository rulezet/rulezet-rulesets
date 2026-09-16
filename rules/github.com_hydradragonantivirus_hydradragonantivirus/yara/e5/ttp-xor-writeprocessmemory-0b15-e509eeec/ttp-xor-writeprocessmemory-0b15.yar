rule TTP_XOR_WriteProcessMemory_0b15 {
  strings:
    $key_0b15 = { 5c 67 [2] 6e 45 [2] 68 70 [2] 46 70 [2] 79 6c }

  condition:
    any of them
}