rule TTP_XOR_WriteProcessMemory_3a67 {
  strings:
    $key_3a67 = { 6d 15 [2] 5f 37 [2] 59 02 [2] 77 02 [2] 48 1e }

  condition:
    any of them
}