rule TTP_XOR_WriteProcessMemory_1779 {
  strings:
    $key_1779 = { 40 0b [2] 72 29 [2] 74 1c [2] 5a 1c [2] 65 00 }

  condition:
    any of them
}