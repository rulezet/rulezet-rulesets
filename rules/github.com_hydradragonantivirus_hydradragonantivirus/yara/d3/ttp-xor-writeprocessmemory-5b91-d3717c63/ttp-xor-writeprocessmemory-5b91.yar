rule TTP_XOR_WriteProcessMemory_5b91 {
  strings:
    $key_5b91 = { 0c e3 [2] 3e c1 [2] 38 f4 [2] 16 f4 [2] 29 e8 }

  condition:
    any of them
}