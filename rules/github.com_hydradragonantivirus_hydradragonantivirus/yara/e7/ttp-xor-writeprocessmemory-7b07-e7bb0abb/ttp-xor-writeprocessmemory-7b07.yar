rule TTP_XOR_WriteProcessMemory_7b07 {
  strings:
    $key_7b07 = { 2c 75 [2] 1e 57 [2] 18 62 [2] 36 62 [2] 09 7e }

  condition:
    any of them
}