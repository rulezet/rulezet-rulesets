rule TTP_XOR_WriteProcessMemory_1282 {
  strings:
    $key_1282 = { 45 f0 [2] 77 d2 [2] 71 e7 [2] 5f e7 [2] 60 fb }

  condition:
    any of them
}