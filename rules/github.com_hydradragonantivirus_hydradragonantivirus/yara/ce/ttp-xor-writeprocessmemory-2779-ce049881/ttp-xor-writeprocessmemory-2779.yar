rule TTP_XOR_WriteProcessMemory_2779 {
  strings:
    $key_2779 = { 70 0b [2] 42 29 [2] 44 1c [2] 6a 1c [2] 55 00 }

  condition:
    any of them
}