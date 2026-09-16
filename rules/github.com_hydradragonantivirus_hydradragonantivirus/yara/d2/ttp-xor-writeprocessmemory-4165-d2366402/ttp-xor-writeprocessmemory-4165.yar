rule TTP_XOR_WriteProcessMemory_4165 {
  strings:
    $key_4165 = { 16 17 [2] 24 35 [2] 22 00 [2] 0c 00 [2] 33 1c }

  condition:
    any of them
}