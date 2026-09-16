rule TTP_XOR_WriteProcessMemory_1293 {
  strings:
    $key_1293 = { 45 e1 [2] 77 c3 [2] 71 f6 [2] 5f f6 [2] 60 ea }

  condition:
    any of them
}