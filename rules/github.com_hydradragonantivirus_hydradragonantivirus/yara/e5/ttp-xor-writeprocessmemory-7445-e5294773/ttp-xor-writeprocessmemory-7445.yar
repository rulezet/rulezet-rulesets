rule TTP_XOR_WriteProcessMemory_7445 {
  strings:
    $key_7445 = { 23 37 [2] 11 15 [2] 17 20 [2] 39 20 [2] 06 3c }

  condition:
    any of them
}