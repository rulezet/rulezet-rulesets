rule TTP_XOR_WriteProcessMemory_1440 {
  strings:
    $key_1440 = { 43 32 [2] 71 10 [2] 77 25 [2] 59 25 [2] 66 39 }

  condition:
    any of them
}