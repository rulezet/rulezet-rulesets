rule TTP_XOR_WriteProcessMemory_08c5 {
  strings:
    $key_08c5 = { 5f b7 [2] 6d 95 [2] 6b a0 [2] 45 a0 [2] 7a bc }

  condition:
    any of them
}