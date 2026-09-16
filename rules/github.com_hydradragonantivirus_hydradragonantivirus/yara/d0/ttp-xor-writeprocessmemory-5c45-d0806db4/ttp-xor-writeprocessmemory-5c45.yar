rule TTP_XOR_WriteProcessMemory_5c45 {
  strings:
    $key_5c45 = { 0b 37 [2] 39 15 [2] 3f 20 [2] 11 20 [2] 2e 3c }

  condition:
    any of them
}