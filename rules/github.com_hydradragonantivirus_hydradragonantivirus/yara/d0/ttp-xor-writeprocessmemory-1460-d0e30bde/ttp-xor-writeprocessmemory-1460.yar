rule TTP_XOR_WriteProcessMemory_1460 {
  strings:
    $key_1460 = { 43 12 [2] 71 30 [2] 77 05 [2] 59 05 [2] 66 19 }

  condition:
    any of them
}