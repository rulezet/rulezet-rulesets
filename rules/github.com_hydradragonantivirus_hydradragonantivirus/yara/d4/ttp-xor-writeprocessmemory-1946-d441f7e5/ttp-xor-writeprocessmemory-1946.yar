rule TTP_XOR_WriteProcessMemory_1946 {
  strings:
    $key_1946 = { 4e 34 [2] 7c 16 [2] 7a 23 [2] 54 23 [2] 6b 3f }

  condition:
    any of them
}