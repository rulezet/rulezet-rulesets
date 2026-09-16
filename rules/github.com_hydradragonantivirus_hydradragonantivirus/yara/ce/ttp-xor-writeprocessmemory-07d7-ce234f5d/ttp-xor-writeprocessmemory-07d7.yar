rule TTP_XOR_WriteProcessMemory_07d7 {
  strings:
    $key_07d7 = { 50 a5 [2] 62 87 [2] 64 b2 [2] 4a b2 [2] 75 ae }

  condition:
    any of them
}