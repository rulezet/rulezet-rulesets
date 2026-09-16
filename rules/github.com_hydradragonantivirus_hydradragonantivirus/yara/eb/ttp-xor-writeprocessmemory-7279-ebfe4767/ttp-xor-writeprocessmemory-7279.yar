rule TTP_XOR_WriteProcessMemory_7279 {
  strings:
    $key_7279 = { 25 0b [2] 17 29 [2] 11 1c [2] 3f 1c [2] 00 00 }

  condition:
    any of them
}