rule TTP_XOR_WriteProcessMemory_45d7 {
  strings:
    $key_45d7 = { 12 a5 [2] 20 87 [2] 26 b2 [2] 08 b2 [2] 37 ae }

  condition:
    any of them
}