rule TTP_XOR_WriteProcessMemory_1221 {
  strings:
    $key_1221 = { 45 53 [2] 77 71 [2] 71 44 [2] 5f 44 [2] 60 58 }

  condition:
    any of them
}