rule TTP_XOR_WriteProcessMemory_3912 {
  strings:
    $key_3912 = { 6e 60 [2] 5c 42 [2] 5a 77 [2] 74 77 [2] 4b 6b }

  condition:
    any of them
}