rule TTP_XOR_WriteProcessMemory_1e07 {
  strings:
    $key_1e07 = { 49 75 [2] 7b 57 [2] 7d 62 [2] 53 62 [2] 6c 7e }

  condition:
    any of them
}