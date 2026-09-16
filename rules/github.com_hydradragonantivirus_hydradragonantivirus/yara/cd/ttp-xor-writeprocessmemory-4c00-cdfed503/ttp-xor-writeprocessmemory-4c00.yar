rule TTP_XOR_WriteProcessMemory_4c00 {
  strings:
    $key_4c00 = { 1b 72 [2] 29 50 [2] 2f 65 [2] 01 65 [2] 3e 79 }

  condition:
    any of them
}