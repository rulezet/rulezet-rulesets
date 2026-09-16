rule TTP_XOR_WriteProcessMemory_f5d7 {
  strings:
    $key_f5d7 = { a2 a5 [2] 90 87 [2] 96 b2 [2] b8 b2 [2] 87 ae }

  condition:
    any of them
}