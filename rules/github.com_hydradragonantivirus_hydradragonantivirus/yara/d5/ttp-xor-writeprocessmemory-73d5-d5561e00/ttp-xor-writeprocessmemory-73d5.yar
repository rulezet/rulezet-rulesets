rule TTP_XOR_WriteProcessMemory_73d5 {
  strings:
    $key_73d5 = { 24 a7 [2] 16 85 [2] 10 b0 [2] 3e b0 [2] 01 ac }

  condition:
    any of them
}