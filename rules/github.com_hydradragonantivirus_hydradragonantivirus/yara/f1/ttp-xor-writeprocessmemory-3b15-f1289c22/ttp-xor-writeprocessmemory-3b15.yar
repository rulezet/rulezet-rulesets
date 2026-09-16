rule TTP_XOR_WriteProcessMemory_3b15 {
  strings:
    $key_3b15 = { 6c 67 [2] 5e 45 [2] 58 70 [2] 76 70 [2] 49 6c }

  condition:
    any of them
}