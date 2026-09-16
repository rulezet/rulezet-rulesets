rule TTP_XOR_WriteProcessMemory_4745 {
  strings:
    $key_4745 = { 10 37 [2] 22 15 [2] 24 20 [2] 0a 20 [2] 35 3c }

  condition:
    any of them
}