rule TTP_XOR_WriteProcessMemory_7240 {
  strings:
    $key_7240 = { 25 32 [2] 17 10 [2] 11 25 [2] 3f 25 [2] 00 39 }

  condition:
    any of them
}