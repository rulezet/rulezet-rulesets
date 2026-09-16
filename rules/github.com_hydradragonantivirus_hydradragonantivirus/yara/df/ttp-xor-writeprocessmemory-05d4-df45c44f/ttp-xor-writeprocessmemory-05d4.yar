rule TTP_XOR_WriteProcessMemory_05d4 {
  strings:
    $key_05d4 = { 52 a6 [2] 60 84 [2] 66 b1 [2] 48 b1 [2] 77 ad }

  condition:
    any of them
}