rule TTP_XOR_WriteProcessMemory_54d7 {
  strings:
    $key_54d7 = { 03 a5 [2] 31 87 [2] 37 b2 [2] 19 b2 [2] 26 ae }

  condition:
    any of them
}