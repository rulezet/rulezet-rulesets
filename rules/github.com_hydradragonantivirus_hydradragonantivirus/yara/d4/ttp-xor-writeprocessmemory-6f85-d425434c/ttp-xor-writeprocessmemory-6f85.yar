rule TTP_XOR_WriteProcessMemory_6f85 {
  strings:
    $key_6f85 = { 38 f7 [2] 0a d5 [2] 0c e0 [2] 22 e0 [2] 1d fc }

  condition:
    any of them
}