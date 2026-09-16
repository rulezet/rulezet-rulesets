rule TTP_XOR_WriteProcessMemory_0b91 {
  strings:
    $key_0b91 = { 5c e3 [2] 6e c1 [2] 68 f4 [2] 46 f4 [2] 79 e8 }

  condition:
    any of them
}