rule TTP_XOR_WriteProcessMemory_12e2 {
  strings:
    $key_12e2 = { 45 90 [2] 77 b2 [2] 71 87 [2] 5f 87 [2] 60 9b }

  condition:
    any of them
}