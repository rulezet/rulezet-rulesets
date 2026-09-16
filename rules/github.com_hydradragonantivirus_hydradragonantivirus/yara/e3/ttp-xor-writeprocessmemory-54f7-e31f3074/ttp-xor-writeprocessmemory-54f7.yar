rule TTP_XOR_WriteProcessMemory_54f7 {
  strings:
    $key_54f7 = { 03 85 [2] 31 a7 [2] 37 92 [2] 19 92 [2] 26 8e }

  condition:
    any of them
}