rule TTP_XOR_WriteProcessMemory_3fa6 {
  strings:
    $key_3fa6 = { 68 d4 [2] 5a f6 [2] 5c c3 [2] 72 c3 [2] 4d df }

  condition:
    any of them
}