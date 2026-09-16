rule TTP_XOR_WriteProcessMemory_1fb3 {
  strings:
    $key_1fb3 = { 48 c1 [2] 7a e3 [2] 7c d6 [2] 52 d6 [2] 6d ca }

  condition:
    any of them
}