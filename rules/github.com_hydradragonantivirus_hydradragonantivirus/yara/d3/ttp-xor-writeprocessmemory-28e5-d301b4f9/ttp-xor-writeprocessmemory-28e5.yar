rule TTP_XOR_WriteProcessMemory_28e5 {
  strings:
    $key_28e5 = { 7f 97 [2] 4d b5 [2] 4b 80 [2] 65 80 [2] 5a 9c }

  condition:
    any of them
}