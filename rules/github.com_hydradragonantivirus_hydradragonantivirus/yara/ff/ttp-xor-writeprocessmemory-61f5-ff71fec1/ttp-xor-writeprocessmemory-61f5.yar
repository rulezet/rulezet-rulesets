rule TTP_XOR_WriteProcessMemory_61f5 {
  strings:
    $key_61f5 = { 36 87 [2] 04 a5 [2] 02 90 [2] 2c 90 [2] 13 8c }

  condition:
    any of them
}