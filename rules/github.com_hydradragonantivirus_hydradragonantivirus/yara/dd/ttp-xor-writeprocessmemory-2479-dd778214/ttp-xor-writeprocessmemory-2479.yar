rule TTP_XOR_WriteProcessMemory_2479 {
  strings:
    $key_2479 = { 73 0b [2] 41 29 [2] 47 1c [2] 69 1c [2] 56 00 }

  condition:
    any of them
}