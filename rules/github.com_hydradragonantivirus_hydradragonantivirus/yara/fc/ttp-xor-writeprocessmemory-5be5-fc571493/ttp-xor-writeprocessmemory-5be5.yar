rule TTP_XOR_WriteProcessMemory_5be5 {
  strings:
    $key_5be5 = { 0c 97 [2] 3e b5 [2] 38 80 [2] 16 80 [2] 29 9c }

  condition:
    any of them
}