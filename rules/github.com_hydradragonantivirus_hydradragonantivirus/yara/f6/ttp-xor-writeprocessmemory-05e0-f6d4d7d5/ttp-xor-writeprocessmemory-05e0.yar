rule TTP_XOR_WriteProcessMemory_05e0 {
  strings:
    $key_05e0 = { 52 92 [2] 60 b0 [2] 66 85 [2] 48 85 [2] 77 99 }

  condition:
    any of them
}