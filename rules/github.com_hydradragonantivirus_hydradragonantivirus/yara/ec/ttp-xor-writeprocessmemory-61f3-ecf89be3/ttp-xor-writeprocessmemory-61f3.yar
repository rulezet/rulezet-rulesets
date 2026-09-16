rule TTP_XOR_WriteProcessMemory_61f3 {
  strings:
    $key_61f3 = { 36 81 [2] 04 a3 [2] 02 96 [2] 2c 96 [2] 13 8a }

  condition:
    any of them
}