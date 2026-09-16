rule TTP_XOR_WriteProcessMemory_1c51 {
  strings:
    $key_1c51 = { 4b 23 [2] 79 01 [2] 7f 34 [2] 51 34 [2] 6e 28 }

  condition:
    any of them
}