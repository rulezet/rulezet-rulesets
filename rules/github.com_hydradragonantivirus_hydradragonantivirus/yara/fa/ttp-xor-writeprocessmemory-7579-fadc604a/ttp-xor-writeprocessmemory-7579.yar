rule TTP_XOR_WriteProcessMemory_7579 {
  strings:
    $key_7579 = { 22 0b [2] 10 29 [2] 16 1c [2] 38 1c [2] 07 00 }

  condition:
    any of them
}