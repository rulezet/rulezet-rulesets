rule TTP_XOR_WriteProcessMemory_4125 {
  strings:
    $key_4125 = { 16 57 [2] 24 75 [2] 22 40 [2] 0c 40 [2] 33 5c }

  condition:
    any of them
}