rule TTP_XOR_WriteProcessMemory_1a40 {
  strings:
    $key_1a40 = { 4d 32 [2] 7f 10 [2] 79 25 [2] 57 25 [2] 68 39 }

  condition:
    any of them
}