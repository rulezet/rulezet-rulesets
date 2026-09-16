rule TTP_XOR_WriteProcessMemory_5b15 {
  strings:
    $key_5b15 = { 0c 67 [2] 3e 45 [2] 38 70 [2] 16 70 [2] 29 6c }

  condition:
    any of them
}