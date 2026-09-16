rule TTP_XOR_WriteProcessMemory_4d17 {
  strings:
    $key_4d17 = { 1a 65 [2] 28 47 [2] 2e 72 [2] 00 72 [2] 3f 6e }

  condition:
    any of them
}