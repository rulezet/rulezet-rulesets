rule TTP_XOR_WriteProcessMemory_6fb3 {
  strings:
    $key_6fb3 = { 38 c1 [2] 0a e3 [2] 0c d6 [2] 22 d6 [2] 1d ca }

  condition:
    any of them
}