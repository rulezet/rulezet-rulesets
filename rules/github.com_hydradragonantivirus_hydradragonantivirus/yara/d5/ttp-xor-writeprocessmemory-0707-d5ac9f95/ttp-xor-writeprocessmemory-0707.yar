rule TTP_XOR_WriteProcessMemory_0707 {
  strings:
    $key_0707 = { 50 75 [2] 62 57 [2] 64 62 [2] 4a 62 [2] 75 7e }

  condition:
    any of them
}