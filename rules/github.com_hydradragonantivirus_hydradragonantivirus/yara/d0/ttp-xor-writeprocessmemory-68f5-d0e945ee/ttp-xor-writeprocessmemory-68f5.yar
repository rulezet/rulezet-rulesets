rule TTP_XOR_WriteProcessMemory_68f5 {
  strings:
    $key_68f5 = { 3f 87 [2] 0d a5 [2] 0b 90 [2] 25 90 [2] 1a 8c }

  condition:
    any of them
}