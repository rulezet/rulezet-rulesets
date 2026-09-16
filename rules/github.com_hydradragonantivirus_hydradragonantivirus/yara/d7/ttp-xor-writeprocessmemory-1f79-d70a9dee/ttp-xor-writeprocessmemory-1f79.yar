rule TTP_XOR_WriteProcessMemory_1f79 {
  strings:
    $key_1f79 = { 48 0b [2] 7a 29 [2] 7c 1c [2] 52 1c [2] 6d 00 }

  condition:
    any of them
}