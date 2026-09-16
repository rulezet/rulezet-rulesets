rule TTP_XOR_WriteProcessMemory_0e07 {
  strings:
    $key_0e07 = { 59 75 [2] 6b 57 [2] 6d 62 [2] 43 62 [2] 7c 7e }

  condition:
    any of them
}