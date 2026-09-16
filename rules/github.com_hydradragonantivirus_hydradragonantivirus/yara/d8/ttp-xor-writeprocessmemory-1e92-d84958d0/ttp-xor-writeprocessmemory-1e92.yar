rule TTP_XOR_WriteProcessMemory_1e92 {
  strings:
    $key_1e92 = { 49 e0 [2] 7b c2 [2] 7d f7 [2] 53 f7 [2] 6c eb }

  condition:
    any of them
}