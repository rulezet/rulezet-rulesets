rule TTP_XOR_WriteProcessMemory_4502 {
  strings:
    $key_4502 = { 12 70 [2] 20 52 [2] 26 67 [2] 08 67 [2] 37 7b }

  condition:
    any of them
}