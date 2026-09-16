rule TTP_XOR_WriteProcessMemory_4782 {
  strings:
    $key_4782 = { 10 f0 [2] 22 d2 [2] 24 e7 [2] 0a e7 [2] 35 fb }

  condition:
    any of them
}