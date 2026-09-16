rule TTP_XOR_WriteProcessMemory_6207 {
  strings:
    $key_6207 = { 35 75 [2] 07 57 [2] 01 62 [2] 2f 62 [2] 10 7e }

  condition:
    any of them
}