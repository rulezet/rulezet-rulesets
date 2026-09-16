rule TTP_XOR_WriteProcessMemory_1a00 {
  strings:
    $key_1a00 = { 4d 72 [2] 7f 50 [2] 79 65 [2] 57 65 [2] 68 79 }

  condition:
    any of them
}