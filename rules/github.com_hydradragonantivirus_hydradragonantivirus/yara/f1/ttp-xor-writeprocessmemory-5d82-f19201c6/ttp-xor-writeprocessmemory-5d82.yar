rule TTP_XOR_WriteProcessMemory_5d82 {
  strings:
    $key_5d82 = { 0a f0 [2] 38 d2 [2] 3e e7 [2] 10 e7 [2] 2f fb }

  condition:
    any of them
}