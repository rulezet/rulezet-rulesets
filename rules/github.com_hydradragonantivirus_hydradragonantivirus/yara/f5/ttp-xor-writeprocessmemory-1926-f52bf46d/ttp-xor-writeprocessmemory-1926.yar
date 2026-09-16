rule TTP_XOR_WriteProcessMemory_1926 {
  strings:
    $key_1926 = { 4e 54 [2] 7c 76 [2] 7a 43 [2] 54 43 [2] 6b 5f }

  condition:
    any of them
}