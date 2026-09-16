rule TTP_XOR_WriteProcessMemory_2282 {
  strings:
    $key_2282 = { 75 f0 [2] 47 d2 [2] 41 e7 [2] 6f e7 [2] 50 fb }

  condition:
    any of them
}