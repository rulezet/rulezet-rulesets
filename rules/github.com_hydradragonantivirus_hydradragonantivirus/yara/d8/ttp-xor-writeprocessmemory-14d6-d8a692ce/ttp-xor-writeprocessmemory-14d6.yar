rule TTP_XOR_WriteProcessMemory_14d6 {
  strings:
    $key_14d6 = { 43 a4 [2] 71 86 [2] 77 b3 [2] 59 b3 [2] 66 af }

  condition:
    any of them
}