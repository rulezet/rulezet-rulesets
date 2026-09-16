rule TTP_XOR_WriteProcessMemory_cc55 {
  strings:
    $key_cc55 = { 9b 27 [2] a9 05 [2] af 30 [2] 81 30 [2] be 2c }

  condition:
    any of them
}