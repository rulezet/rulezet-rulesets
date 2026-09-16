rule TTP_XOR_WriteProcessMemory_7b94 {
  strings:
    $key_7b94 = { 2c e6 [2] 1e c4 [2] 18 f1 [2] 36 f1 [2] 09 ed }

  condition:
    any of them
}