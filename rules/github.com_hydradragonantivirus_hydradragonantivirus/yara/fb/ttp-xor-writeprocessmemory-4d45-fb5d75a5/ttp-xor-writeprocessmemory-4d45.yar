rule TTP_XOR_WriteProcessMemory_4d45 {
  strings:
    $key_4d45 = { 1a 37 [2] 28 15 [2] 2e 20 [2] 00 20 [2] 3f 3c }

  condition:
    any of them
}