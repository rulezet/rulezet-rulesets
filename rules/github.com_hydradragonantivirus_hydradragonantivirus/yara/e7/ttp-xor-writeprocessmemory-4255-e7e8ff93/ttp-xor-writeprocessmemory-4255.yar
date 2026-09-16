rule TTP_XOR_WriteProcessMemory_4255 {
  strings:
    $key_4255 = { 15 27 [2] 27 05 [2] 21 30 [2] 0f 30 [2] 30 2c }

  condition:
    any of them
}