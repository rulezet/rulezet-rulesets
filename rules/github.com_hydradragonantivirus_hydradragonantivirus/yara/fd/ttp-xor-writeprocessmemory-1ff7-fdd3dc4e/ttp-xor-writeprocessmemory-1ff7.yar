rule TTP_XOR_WriteProcessMemory_1ff7 {
  strings:
    $key_1ff7 = { 48 85 [2] 7a a7 [2] 7c 92 [2] 52 92 [2] 6d 8e }

  condition:
    any of them
}