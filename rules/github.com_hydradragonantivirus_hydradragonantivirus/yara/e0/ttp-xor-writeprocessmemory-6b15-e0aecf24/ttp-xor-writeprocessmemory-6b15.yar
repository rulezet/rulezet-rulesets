rule TTP_XOR_WriteProcessMemory_6b15 {
  strings:
    $key_6b15 = { 3c 67 [2] 0e 45 [2] 08 70 [2] 26 70 [2] 19 6c }

  condition:
    any of them
}