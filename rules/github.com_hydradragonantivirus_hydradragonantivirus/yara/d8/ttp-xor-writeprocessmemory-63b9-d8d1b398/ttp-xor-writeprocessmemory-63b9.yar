rule TTP_XOR_WriteProcessMemory_63b9 {
  strings:
    $key_63b9 = { 34 cb [2] 06 e9 [2] 00 dc [2] 2e dc [2] 11 c0 }

  condition:
    any of them
}