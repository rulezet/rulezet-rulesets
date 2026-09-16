rule TTP_XOR_WriteProcessMemory_4d71 {
  strings:
    $key_4d71 = { 1a 03 [2] 28 21 [2] 2e 14 [2] 00 14 [2] 3f 08 }

  condition:
    any of them
}