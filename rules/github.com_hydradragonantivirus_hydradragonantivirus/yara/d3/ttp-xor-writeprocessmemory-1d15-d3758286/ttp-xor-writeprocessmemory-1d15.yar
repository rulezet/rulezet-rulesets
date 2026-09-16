rule TTP_XOR_WriteProcessMemory_1d15 {
  strings:
    $key_1d15 = { 4a 67 [2] 78 45 [2] 7e 70 [2] 50 70 [2] 6f 6c }

  condition:
    any of them
}