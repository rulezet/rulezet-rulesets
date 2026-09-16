rule TTP_XOR_WriteProcessMemory_2c47 {
  strings:
    $key_2c47 = { 7b 35 [2] 49 17 [2] 4f 22 [2] 61 22 [2] 5e 3e }

  condition:
    any of them
}