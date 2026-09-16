rule TTP_XOR_WriteProcessMemory_4179 {
  strings:
    $key_4179 = { 16 0b [2] 24 29 [2] 22 1c [2] 0c 1c [2] 33 00 }

  condition:
    any of them
}