rule TTP_XOR_WriteProcessMemory_0d00 {
  strings:
    $key_0d00 = { 5a 72 [2] 68 50 [2] 6e 65 [2] 40 65 [2] 7f 79 }

  condition:
    any of them
}