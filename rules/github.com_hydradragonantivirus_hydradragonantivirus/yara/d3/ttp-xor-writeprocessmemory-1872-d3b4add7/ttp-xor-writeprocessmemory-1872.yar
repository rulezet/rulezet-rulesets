rule TTP_XOR_WriteProcessMemory_1872 {
  strings:
    $key_1872 = { 4f 00 [2] 7d 22 [2] 7b 17 [2] 55 17 [2] 6a 0b }

  condition:
    any of them
}