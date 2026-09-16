rule TTP_XOR_WriteProcessMemory_1ec5 {
  strings:
    $key_1ec5 = { 49 b7 [2] 7b 95 [2] 7d a0 [2] 53 a0 [2] 6c bc }

  condition:
    any of them
}