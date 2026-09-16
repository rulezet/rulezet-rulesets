rule TTP_XOR_WriteProcessMemory_1cf6 {
  strings:
    $key_1cf6 = { 4b 84 [2] 79 a6 [2] 7f 93 [2] 51 93 [2] 6e 8f }

  condition:
    any of them
}