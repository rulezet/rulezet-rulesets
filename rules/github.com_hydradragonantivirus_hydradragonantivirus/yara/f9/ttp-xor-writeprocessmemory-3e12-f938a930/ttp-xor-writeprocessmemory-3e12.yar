rule TTP_XOR_WriteProcessMemory_3e12 {
  strings:
    $key_3e12 = { 69 60 [2] 5b 42 [2] 5d 77 [2] 73 77 [2] 4c 6b }

  condition:
    any of them
}