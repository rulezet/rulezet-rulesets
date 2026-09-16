rule TTP_XOR_WriteProcessMemory_19c3 {
  strings:
    $key_19c3 = { 4e b1 [2] 7c 93 [2] 7a a6 [2] 54 a6 [2] 6b ba }

  condition:
    any of them
}