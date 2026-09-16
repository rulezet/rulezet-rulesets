rule TTP_XOR_WriteProcessMemory_1cf7 {
  strings:
    $key_1cf7 = { 4b 85 [2] 79 a7 [2] 7f 92 [2] 51 92 [2] 6e 8e }

  condition:
    any of them
}