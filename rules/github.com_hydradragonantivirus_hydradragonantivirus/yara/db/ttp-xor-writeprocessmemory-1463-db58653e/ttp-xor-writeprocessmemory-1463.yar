rule TTP_XOR_WriteProcessMemory_1463 {
  strings:
    $key_1463 = { 43 11 [2] 71 33 [2] 77 06 [2] 59 06 [2] 66 1a }

  condition:
    any of them
}