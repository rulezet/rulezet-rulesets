rule TTP_XOR_WriteProcessMemory_73e5 {
  strings:
    $key_73e5 = { 24 97 [2] 16 b5 [2] 10 80 [2] 3e 80 [2] 01 9c }

  condition:
    any of them
}