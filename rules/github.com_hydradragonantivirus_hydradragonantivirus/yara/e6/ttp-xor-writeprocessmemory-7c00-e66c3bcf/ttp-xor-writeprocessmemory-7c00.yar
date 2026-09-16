rule TTP_XOR_WriteProcessMemory_7c00 {
  strings:
    $key_7c00 = { 2b 72 [2] 19 50 [2] 1f 65 [2] 31 65 [2] 0e 79 }

  condition:
    any of them
}