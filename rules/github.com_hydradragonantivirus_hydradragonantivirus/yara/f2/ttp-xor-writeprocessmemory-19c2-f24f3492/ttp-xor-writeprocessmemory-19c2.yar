rule TTP_XOR_WriteProcessMemory_19c2 {
  strings:
    $key_19c2 = { 4e b0 [2] 7c 92 [2] 7a a7 [2] 54 a7 [2] 6b bb }

  condition:
    any of them
}