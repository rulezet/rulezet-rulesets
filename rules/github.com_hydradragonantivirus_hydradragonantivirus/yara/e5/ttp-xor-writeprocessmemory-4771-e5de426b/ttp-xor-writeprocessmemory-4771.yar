rule TTP_XOR_WriteProcessMemory_4771 {
  strings:
    $key_4771 = { 10 03 [2] 22 21 [2] 24 14 [2] 0a 14 [2] 35 08 }

  condition:
    any of them
}