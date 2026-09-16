rule TTP_XOR_WriteProcessMemory_1d85 {
  strings:
    $key_1d85 = { 4a f7 [2] 78 d5 [2] 7e e0 [2] 50 e0 [2] 6f fc }

  condition:
    any of them
}