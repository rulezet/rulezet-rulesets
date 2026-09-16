rule TTP_XOR_WriteProcessMemory_0579 {
  strings:
    $key_0579 = { 52 0b [2] 60 29 [2] 66 1c [2] 48 1c [2] 77 00 }

  condition:
    any of them
}