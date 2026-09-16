rule TTP_XOR_WriteProcessMemory_6f45 {
  strings:
    $key_6f45 = { 38 37 [2] 0a 15 [2] 0c 20 [2] 22 20 [2] 1d 3c }

  condition:
    any of them
}