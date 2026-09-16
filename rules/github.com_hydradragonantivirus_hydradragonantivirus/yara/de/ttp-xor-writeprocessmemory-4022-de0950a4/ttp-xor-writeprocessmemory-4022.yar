rule TTP_XOR_WriteProcessMemory_4022 {
  strings:
    $key_4022 = { 17 50 [2] 25 72 [2] 23 47 [2] 0d 47 [2] 32 5b }

  condition:
    any of them
}