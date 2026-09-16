rule TTP_XOR_WriteProcessMemory_0b94 {
  strings:
    $key_0b94 = { 5c e6 [2] 6e c4 [2] 68 f1 [2] 46 f1 [2] 79 ed }

  condition:
    any of them
}