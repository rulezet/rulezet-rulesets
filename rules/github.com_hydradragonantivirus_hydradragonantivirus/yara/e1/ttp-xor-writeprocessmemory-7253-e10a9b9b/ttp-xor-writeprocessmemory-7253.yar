rule TTP_XOR_WriteProcessMemory_7253 {
  strings:
    $key_7253 = { 25 21 [2] 17 03 [2] 11 36 [2] 3f 36 [2] 00 2a }

  condition:
    any of them
}