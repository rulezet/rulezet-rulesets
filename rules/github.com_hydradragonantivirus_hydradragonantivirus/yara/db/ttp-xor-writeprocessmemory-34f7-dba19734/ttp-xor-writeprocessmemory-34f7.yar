rule TTP_XOR_WriteProcessMemory_34f7 {
  strings:
    $key_34f7 = { 63 85 [2] 51 a7 [2] 57 92 [2] 79 92 [2] 46 8e }

  condition:
    any of them
}