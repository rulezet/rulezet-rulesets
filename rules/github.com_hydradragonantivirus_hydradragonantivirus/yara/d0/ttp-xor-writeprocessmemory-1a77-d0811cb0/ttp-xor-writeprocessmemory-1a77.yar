rule TTP_XOR_WriteProcessMemory_1a77 {
  strings:
    $key_1a77 = { 4d 05 [2] 7f 27 [2] 79 12 [2] 57 12 [2] 68 0e }

  condition:
    any of them
}