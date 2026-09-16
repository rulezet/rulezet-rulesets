rule TTP_XOR_WriteProcessMemory_7282 {
  strings:
    $key_7282 = { 25 f0 [2] 17 d2 [2] 11 e7 [2] 3f e7 [2] 00 fb }

  condition:
    any of them
}