rule TTP_XOR_WriteProcessMemory_5465 {
  strings:
    $key_5465 = { 03 17 [2] 31 35 [2] 37 00 [2] 19 00 [2] 26 1c }

  condition:
    any of them
}