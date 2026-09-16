rule TTP_XOR_WriteProcessMemory_0f84 {
  strings:
    $key_0f84 = { 58 f6 [2] 6a d4 [2] 6c e1 [2] 42 e1 [2] 7d fd }

  condition:
    any of them
}