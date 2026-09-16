rule TTP_XOR_WriteProcessMemory_1307 {
  strings:
    $key_1307 = { 44 75 [2] 76 57 [2] 70 62 [2] 5e 62 [2] 61 7e }

  condition:
    any of them
}