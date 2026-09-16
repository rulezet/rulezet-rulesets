rule TTP_XOR_WriteProcessMemory_74f7 {
  strings:
    $key_74f7 = { 23 85 [2] 11 a7 [2] 17 92 [2] 39 92 [2] 06 8e }

  condition:
    any of them
}