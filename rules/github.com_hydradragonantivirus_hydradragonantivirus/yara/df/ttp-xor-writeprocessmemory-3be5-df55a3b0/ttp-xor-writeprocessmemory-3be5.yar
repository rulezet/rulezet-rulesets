rule TTP_XOR_WriteProcessMemory_3be5 {
  strings:
    $key_3be5 = { 6c 97 [2] 5e b5 [2] 58 80 [2] 76 80 [2] 49 9c }

  condition:
    any of them
}