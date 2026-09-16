rule TTP_XOR_WriteProcessMemory_3db3 {
  strings:
    $key_3db3 = { 6a c1 [2] 58 e3 [2] 5e d6 [2] 70 d6 [2] 4f ca }

  condition:
    any of them
}