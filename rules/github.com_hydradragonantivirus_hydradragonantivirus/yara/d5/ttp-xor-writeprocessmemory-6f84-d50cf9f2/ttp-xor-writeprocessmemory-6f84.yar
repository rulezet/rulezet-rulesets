rule TTP_XOR_WriteProcessMemory_6f84 {
  strings:
    $key_6f84 = { 38 f6 [2] 0a d4 [2] 0c e1 [2] 22 e1 [2] 1d fd }

  condition:
    any of them
}