rule TTP_XOR_WriteProcessMemory_1e25 {
  strings:
    $key_1e25 = { 49 57 [2] 7b 75 [2] 7d 40 [2] 53 40 [2] 6c 5c }

  condition:
    any of them
}