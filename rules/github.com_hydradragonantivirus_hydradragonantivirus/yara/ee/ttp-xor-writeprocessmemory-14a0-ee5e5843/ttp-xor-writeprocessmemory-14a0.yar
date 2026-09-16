rule TTP_XOR_WriteProcessMemory_14a0 {
  strings:
    $key_14a0 = { 43 d2 [2] 71 f0 [2] 77 c5 [2] 59 c5 [2] 66 d9 }

  condition:
    any of them
}