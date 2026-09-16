rule TTP_XOR_WriteProcessMemory_7d72 {
  strings:
    $key_7d72 = { 2a 00 [2] 18 22 [2] 1e 17 [2] 30 17 [2] 0f 0b }

  condition:
    any of them
}