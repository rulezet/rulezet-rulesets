rule TTP_XOR_WriteProcessMemory_5579 {
  strings:
    $key_5579 = { 02 0b [2] 30 29 [2] 36 1c [2] 18 1c [2] 27 00 }

  condition:
    any of them
}