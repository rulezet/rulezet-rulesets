rule TTP_XOR_WriteProcessMemory_05c0 {
  strings:
    $key_05c0 = { 52 b2 [2] 60 90 [2] 66 a5 [2] 48 a5 [2] 77 b9 }

  condition:
    any of them
}