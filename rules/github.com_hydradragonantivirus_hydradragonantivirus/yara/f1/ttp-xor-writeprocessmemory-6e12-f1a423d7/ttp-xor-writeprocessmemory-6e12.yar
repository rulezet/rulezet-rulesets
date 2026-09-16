rule TTP_XOR_WriteProcessMemory_6e12 {
  strings:
    $key_6e12 = { 39 60 [2] 0b 42 [2] 0d 77 [2] 23 77 [2] 1c 6b }

  condition:
    any of them
}