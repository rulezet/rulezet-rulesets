rule TTP_XOR_WriteProcessMemory_65d7 {
  strings:
    $key_65d7 = { 32 a5 [2] 00 87 [2] 06 b2 [2] 28 b2 [2] 17 ae }

  condition:
    any of them
}