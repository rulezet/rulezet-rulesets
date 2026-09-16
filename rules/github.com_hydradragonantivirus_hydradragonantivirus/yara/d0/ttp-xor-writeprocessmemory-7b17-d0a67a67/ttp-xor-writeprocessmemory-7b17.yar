rule TTP_XOR_WriteProcessMemory_7b17 {
  strings:
    $key_7b17 = { 2c 65 [2] 1e 47 [2] 18 72 [2] 36 72 [2] 09 6e }

  condition:
    any of them
}