rule TTP_XOR_WriteProcessMemory_f6d7 {
  strings:
    $key_f6d7 = { a1 a5 [2] 93 87 [2] 95 b2 [2] bb b2 [2] 84 ae }

  condition:
    any of them
}