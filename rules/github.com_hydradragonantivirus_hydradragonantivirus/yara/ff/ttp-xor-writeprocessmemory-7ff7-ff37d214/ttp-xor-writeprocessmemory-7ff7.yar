rule TTP_XOR_WriteProcessMemory_7ff7 {
  strings:
    $key_7ff7 = { 28 85 [2] 1a a7 [2] 1c 92 [2] 32 92 [2] 0d 8e }

  condition:
    any of them
}