rule TTP_XOR_WriteProcessMemory_5b25 {
  strings:
    $key_5b25 = { 0c 57 [2] 3e 75 [2] 38 40 [2] 16 40 [2] 29 5c }

  condition:
    any of them
}