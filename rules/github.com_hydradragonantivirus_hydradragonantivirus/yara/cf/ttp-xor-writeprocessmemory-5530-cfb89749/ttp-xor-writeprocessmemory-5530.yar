rule TTP_XOR_WriteProcessMemory_5530 {
  strings:
    $key_5530 = { 02 42 [2] 30 60 [2] 36 55 [2] 18 55 [2] 27 49 }

  condition:
    any of them
}