rule TTP_XOR_WriteProcessMemory_1202 {
  strings:
    $key_1202 = { 45 70 [2] 77 52 [2] 71 67 [2] 5f 67 [2] 60 7b }

  condition:
    any of them
}