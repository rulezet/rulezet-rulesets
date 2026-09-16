rule TTP_XOR_WriteProcessMemory_77d7 {
  strings:
    $key_77d7 = { 20 a5 [2] 12 87 [2] 14 b2 [2] 3a b2 [2] 05 ae }

  condition:
    any of them
}