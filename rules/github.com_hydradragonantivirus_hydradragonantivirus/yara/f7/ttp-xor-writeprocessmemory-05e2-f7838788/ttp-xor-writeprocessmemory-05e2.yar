rule TTP_XOR_WriteProcessMemory_05e2 {
  strings:
    $key_05e2 = { 52 90 [2] 60 b2 [2] 66 87 [2] 48 87 [2] 77 9b }

  condition:
    any of them
}