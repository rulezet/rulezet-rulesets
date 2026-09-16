rule TTP_XOR_WriteProcessMemory_19c5 {
  strings:
    $key_19c5 = { 4e b7 [2] 7c 95 [2] 7a a0 [2] 54 a0 [2] 6b bc }

  condition:
    any of them
}