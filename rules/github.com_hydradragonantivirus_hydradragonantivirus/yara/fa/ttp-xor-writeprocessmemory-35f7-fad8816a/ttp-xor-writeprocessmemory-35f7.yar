rule TTP_XOR_WriteProcessMemory_35f7 {
  strings:
    $key_35f7 = { 62 85 [2] 50 a7 [2] 56 92 [2] 78 92 [2] 47 8e }

  condition:
    any of them
}