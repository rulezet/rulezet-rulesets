rule TTP_XOR_WriteProcessMemory_1247 {
  strings:
    $key_1247 = { 45 35 [2] 77 17 [2] 71 22 [2] 5f 22 [2] 60 3e }

  condition:
    any of them
}