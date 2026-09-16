rule TTP_XOR_WriteProcessMemory_3f45 {
  strings:
    $key_3f45 = { 68 37 [2] 5a 15 [2] 5c 20 [2] 72 20 [2] 4d 3c }

  condition:
    any of them
}