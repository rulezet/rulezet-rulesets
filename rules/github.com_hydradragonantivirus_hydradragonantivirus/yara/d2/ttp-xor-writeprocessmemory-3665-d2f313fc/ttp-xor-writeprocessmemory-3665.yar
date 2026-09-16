rule TTP_XOR_WriteProcessMemory_3665 {
  strings:
    $key_3665 = { 61 17 [2] 53 35 [2] 55 00 [2] 7b 00 [2] 44 1c }

  condition:
    any of them
}