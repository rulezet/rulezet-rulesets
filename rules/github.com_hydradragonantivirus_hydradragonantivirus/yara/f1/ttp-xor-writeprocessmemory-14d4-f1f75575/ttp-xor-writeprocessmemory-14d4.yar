rule TTP_XOR_WriteProcessMemory_14d4 {
  strings:
    $key_14d4 = { 43 a6 [2] 71 84 [2] 77 b1 [2] 59 b1 [2] 66 ad }

  condition:
    any of them
}