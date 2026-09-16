rule TTP_XOR_WriteProcessMemory_1431 {
  strings:
    $key_1431 = { 43 43 [2] 71 61 [2] 77 54 [2] 59 54 [2] 66 48 }

  condition:
    any of them
}