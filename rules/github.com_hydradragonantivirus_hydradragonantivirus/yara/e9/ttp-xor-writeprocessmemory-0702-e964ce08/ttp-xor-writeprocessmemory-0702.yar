rule TTP_XOR_WriteProcessMemory_0702 {
  strings:
    $key_0702 = { 50 70 [2] 62 52 [2] 64 67 [2] 4a 67 [2] 75 7b }

  condition:
    any of them
}