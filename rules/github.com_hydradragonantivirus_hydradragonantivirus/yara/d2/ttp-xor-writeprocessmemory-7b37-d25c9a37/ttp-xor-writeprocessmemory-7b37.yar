rule TTP_XOR_WriteProcessMemory_7b37 {
  strings:
    $key_7b37 = { 2c 45 [2] 1e 67 [2] 18 52 [2] 36 52 [2] 09 4e }

  condition:
    any of them
}