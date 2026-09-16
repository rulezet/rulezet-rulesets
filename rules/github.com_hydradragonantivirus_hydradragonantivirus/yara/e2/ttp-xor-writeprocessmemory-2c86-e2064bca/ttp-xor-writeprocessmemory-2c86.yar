rule TTP_XOR_WriteProcessMemory_2c86 {
  strings:
    $key_2c86 = { 7b f4 [2] 49 d6 [2] 4f e3 [2] 61 e3 [2] 5e ff }

  condition:
    any of them
}