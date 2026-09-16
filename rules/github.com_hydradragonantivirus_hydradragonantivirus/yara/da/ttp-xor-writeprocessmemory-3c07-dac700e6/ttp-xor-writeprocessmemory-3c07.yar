rule TTP_XOR_WriteProcessMemory_3c07 {
  strings:
    $key_3c07 = { 6b 75 [2] 59 57 [2] 5f 62 [2] 71 62 [2] 4e 7e }

  condition:
    any of them
}