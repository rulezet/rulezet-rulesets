rule TTP_XOR_WriteProcessMemory_0e12 {
  strings:
    $key_0e12 = { 59 60 [2] 6b 42 [2] 6d 77 [2] 43 77 [2] 7c 6b }

  condition:
    any of them
}