rule TTP_XOR_WriteProcessMemory_1327 {
  strings:
    $key_1327 = { 44 55 [2] 76 77 [2] 70 42 [2] 5e 42 [2] 61 5e }

  condition:
    any of them
}