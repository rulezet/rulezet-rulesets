rule TTP_XOR_WriteProcessMemory_5794 {
  strings:
    $key_5794 = { 00 e6 [2] 32 c4 [2] 34 f1 [2] 1a f1 [2] 25 ed }

  condition:
    any of them
}