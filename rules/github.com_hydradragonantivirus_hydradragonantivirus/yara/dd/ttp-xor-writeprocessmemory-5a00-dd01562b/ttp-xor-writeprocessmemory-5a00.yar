rule TTP_XOR_WriteProcessMemory_5a00 {
  strings:
    $key_5a00 = { 0d 72 [2] 3f 50 [2] 39 65 [2] 17 65 [2] 28 79 }

  condition:
    any of them
}