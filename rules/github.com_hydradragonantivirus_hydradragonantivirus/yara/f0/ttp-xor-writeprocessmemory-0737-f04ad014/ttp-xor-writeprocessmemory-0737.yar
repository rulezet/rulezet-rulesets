rule TTP_XOR_WriteProcessMemory_0737 {
  strings:
    $key_0737 = { 50 45 [2] 62 67 [2] 64 52 [2] 4a 52 [2] 75 4e }

  condition:
    any of them
}