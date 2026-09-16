rule TTP_XOR_WriteProcessMemory_51f7 {
  strings:
    $key_51f7 = { 06 85 [2] 34 a7 [2] 32 92 [2] 1c 92 [2] 23 8e }

  condition:
    any of them
}