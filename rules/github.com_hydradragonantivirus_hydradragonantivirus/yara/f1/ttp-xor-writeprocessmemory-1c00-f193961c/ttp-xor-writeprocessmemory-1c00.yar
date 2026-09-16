rule TTP_XOR_WriteProcessMemory_1c00 {
  strings:
    $key_1c00 = { 4b 72 [2] 79 50 [2] 7f 65 [2] 51 65 [2] 6e 79 }

  condition:
    any of them
}