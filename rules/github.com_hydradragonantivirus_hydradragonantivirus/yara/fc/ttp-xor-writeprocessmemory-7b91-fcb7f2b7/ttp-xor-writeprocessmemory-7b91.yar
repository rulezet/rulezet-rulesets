rule TTP_XOR_WriteProcessMemory_7b91 {
  strings:
    $key_7b91 = { 2c e3 [2] 1e c1 [2] 18 f4 [2] 36 f4 [2] 09 e8 }

  condition:
    any of them
}