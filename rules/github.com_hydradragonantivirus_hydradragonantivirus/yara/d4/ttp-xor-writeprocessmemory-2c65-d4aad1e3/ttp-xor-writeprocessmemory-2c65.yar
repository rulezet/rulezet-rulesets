rule TTP_XOR_WriteProcessMemory_2c65 {
  strings:
    $key_2c65 = { 7b 17 [2] 49 35 [2] 4f 00 [2] 61 00 [2] 5e 1c }

  condition:
    any of them
}