rule TTP_XOR_WriteProcessMemory_61e7 {
  strings:
    $key_61e7 = { 36 95 [2] 04 b7 [2] 02 82 [2] 2c 82 [2] 13 9e }

  condition:
    any of them
}