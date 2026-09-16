rule TTP_XOR_WriteProcessMemory_15d7 {
  strings:
    $key_15d7 = { 42 a5 [2] 70 87 [2] 76 b2 [2] 58 b2 [2] 67 ae }

  condition:
    any of them
}