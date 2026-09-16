rule TTP_XOR_WriteProcessMemory_6855 {
  strings:
    $key_6855 = { 3f 27 [2] 0d 05 [2] 0b 30 [2] 25 30 [2] 1a 2c }

  condition:
    any of them
}