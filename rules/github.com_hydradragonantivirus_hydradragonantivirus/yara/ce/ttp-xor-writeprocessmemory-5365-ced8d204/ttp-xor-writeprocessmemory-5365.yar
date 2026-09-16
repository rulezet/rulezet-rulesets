rule TTP_XOR_WriteProcessMemory_5365 {
  strings:
    $key_5365 = { 04 17 [2] 36 35 [2] 30 00 [2] 1e 00 [2] 21 1c }

  condition:
    any of them
}