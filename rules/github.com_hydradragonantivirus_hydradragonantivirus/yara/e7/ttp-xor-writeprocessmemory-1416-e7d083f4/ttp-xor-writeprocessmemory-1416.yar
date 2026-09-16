rule TTP_XOR_WriteProcessMemory_1416 {
  strings:
    $key_1416 = { 43 64 [2] 71 46 [2] 77 73 [2] 59 73 [2] 66 6f }

  condition:
    any of them
}