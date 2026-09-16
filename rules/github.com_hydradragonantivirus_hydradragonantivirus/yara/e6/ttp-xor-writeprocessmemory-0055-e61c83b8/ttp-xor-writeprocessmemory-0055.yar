rule TTP_XOR_WriteProcessMemory_0055 {
  strings:
    $key_0055 = { 57 27 [2] 65 05 [2] 63 30 [2] 4d 30 [2] 72 2c }

  condition:
    any of them
}