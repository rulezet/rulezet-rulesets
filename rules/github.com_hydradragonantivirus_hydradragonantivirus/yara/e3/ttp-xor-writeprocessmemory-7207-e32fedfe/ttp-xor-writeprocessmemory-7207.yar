rule TTP_XOR_WriteProcessMemory_7207 {
  strings:
    $key_7207 = { 25 75 [2] 17 57 [2] 11 62 [2] 3f 62 [2] 00 7e }

  condition:
    any of them
}