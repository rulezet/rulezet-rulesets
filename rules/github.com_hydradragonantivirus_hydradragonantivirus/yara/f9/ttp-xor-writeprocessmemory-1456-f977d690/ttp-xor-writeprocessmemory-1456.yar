rule TTP_XOR_WriteProcessMemory_1456 {
  strings:
    $key_1456 = { 43 24 [2] 71 06 [2] 77 33 [2] 59 33 [2] 66 2f }

  condition:
    any of them
}